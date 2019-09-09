/*
    Socle - Socket Library Ecosystem
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    This library  is free  software;  you can redistribute  it and/or
    modify  it  under   the  terms of the  GNU Lesser  General Public
    License  as published by  the   Free Software Foundation;  either
    version 3.0 of the License, or (at your option) any later version.
    This library is  distributed  in the hope that  it will be useful,
    but WITHOUT ANY WARRANTY;  without  even  the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
    
    See the GNU Lesser General Public License for more details.
    
    You  should have received a copy of the GNU Lesser General Public
    License along with this library.
*/

#ifndef __TRAFLOG_HPP__
#define __TRAFLOG_HPP__

#include <baseproxy.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fstream>
#include <iostream>

#include <sobject.hpp>

namespace socle {

struct expiring_fd : public expiring_int {
    ~expiring_fd() override {
        ::close(value());
    }
};

class expiring_ofstream : public expiring_ptr<std::ofstream> {

public:
    expiring_ofstream(std::ofstream* o, unsigned int sec) : expiring_ptr<std::ofstream>(o, sec) {};
    ~expiring_ofstream() override {

        auto* optr = dynamic_cast<std::ofstream*>(value());
        if(optr) {
            if(optr->is_open()) {
                optr->flush();
                optr->close();
            }
        }
    }

    bool expired() override  {
        auto log = logan::create("socle.expiring_ofstream");
        auto r = expiring_ptr<std::ofstream>::expired();

        log.deb("0x%x: now=%d expired_at=%d, result=%d", value(), time(nullptr), expired_at(), r);

        return r;
    }

    static bool is_expired(expiring_ofstream *ptr) { return ptr->expired(); }
};


class baseFileWriter {
public:
    // returns number of written bytes in str written into fnm
    virtual std::size_t write(std::string const& fnm, std::string const& str) = 0;

    // unguaranteed flush - stream will be flushed to disk if possible
    virtual bool flush(std::string const& fnm) = 0;

    // open the file
    virtual bool open(std::string const& fnm) = 0;

    // close the file
    virtual bool close(std::string const& fnm) = 0;

    // is this writer opened?
    virtual bool opened() = 0;
    virtual ~baseFileWriter() = default;
};

class poolFileWriter : public baseFileWriter {


    explicit poolFileWriter(): ofstream_pool("ofstream-pool", 30, true ) {
        ofstream_pool.expiration_check(expiring_ofstream::is_expired);
        ofstream_pool.opportunistic_removal(2);

        log = logan::create("socle.poolFileWriter");
    }

public:
    poolFileWriter& operator=(poolFileWriter const&) = delete;
    poolFileWriter(poolFileWriter const&) = delete;

    static poolFileWriter* instance() {
        static poolFileWriter w = poolFileWriter();
        return &w;
    }

    std::size_t write(std::string const& fnm, std::string const& str) override {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto o = get_ofstream(fnm);

        if(!o) return 0;

        (*o) << str;


        auto sz = str.size();

        log.dia("file: %s: written %dB", fnm.c_str(), sz);
        return sz;
    };

    std::ofstream* get_ofstream(std::string const& fnm, bool create = true) {
        auto optr = ofstream_pool.get(fnm);
        if (! optr) {

            if(! create) {
                log.dia("file: %s: stream not found.", fnm.c_str());
                return nullptr;
            }

            log.dia("file: %s: creating a new stream", fnm.c_str());

            for(auto s: ofstream_pool.items()) {
                log.deb("pool item: %s", s.c_str());
            }

            auto* stream = new std::ofstream(fnm , std::ofstream::out | std::ofstream::app);
            ofstream_pool.set(fnm, new expiring_ofstream(stream, 60));

            return stream;
        } else {
            log.deb("file: %s: existing stream", fnm.c_str());
            return optr->value();
        }
    }

    bool flush(std::string const& fnm) override {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto o = get_ofstream(fnm, false);
        if(o) {
            o->flush();
            log.dia("file: %s: flushed", fnm.c_str());
            return true;
        }

        return false;
    }

    bool close(std::string const& fnm) override {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto o = get_ofstream(fnm, false);
        if(o) {
            ofstream_pool.erase(fnm);

            log.dia("file: %s: erased", fnm.c_str());
            return true;
        }

        return false;
    }

    // trafLog compatible API
    bool open(std::string const& fnm) override {

        auto* o = get_ofstream(fnm);

        return o != nullptr;
    }

    // pool writer is always opened
    bool opened() override { return true; };

private:
    logan_lite log;

    // pool of opened streams. If expired, they will be closed and destruct.
    ptr_cache<std::string, expiring_ofstream> ofstream_pool;
};

class fileWriter : public baseFileWriter {

    std::ofstream* writer_;
    bool opened_;
    std::string filename_;

public:
    explicit fileWriter() : writer_(nullptr), opened_(false) {};

    bool opened() override { return opened_; }
    inline void opened(bool b) { opened_ = b; }

    inline std::string filename() const { return filename_; };

    std::size_t write(std::string const&fnm, std::string const& str) override {

        if(! writer_) return 0;

        *writer_ << str;
        return str.size();
    }

    bool open(std::string const& fnm) override {

        if(writer_) return true;

        if(fnm.empty()) {
            return false;
        }

        writer_ = new std::ofstream(fnm , std::ofstream::out | std::ofstream::app);
        if(writer_->is_open()) {
            filename_ = fnm;
            opened(true);
            return true;
        }

        close();
        return false;
    }

    bool close(std::string const& fnm) override {
        close();

        return !opened();
    }

    virtual void close() {
        opened(false);

        if(writer_) {
            if(writer_->is_open()) {
                writer_->close();
            }

            delete writer_;
            writer_ = nullptr;
            filename_.clear();
        }
    }

    bool flush(std::string const& fnm) override {
        if(writer_) {
            writer_->flush();

            return true;
        }

        return false;

    }
};

class trafLog : public sobject {

    static const bool use_pool_writer = true;

public:
	trafLog(baseProxy *p,const char* d_dir, const char* f_prefix, const char* f_suffix) : sobject(),
    proxy_(p),
	status_(true),
	data_dir(d_dir),
	file_prefix(f_prefix),
	file_suffix(f_suffix),
	writer_key_l_("???:???"),
	writer_key_r_("???:???") {
        create_writer_key();
        proxy_ = nullptr;

        if(!use_pool_writer) {
            writer_ = new fileWriter();
        } else {
            writer_ = poolFileWriter::instance();
        }
	}
	
	~trafLog() override {

	    if(writer_) {
	        if(! writer_key_.empty()) {
	            writer_->close(writer_key_);
	        }
	    }

	    if(! use_pool_writer)
	        delete writer_;
	};

    bool ask_destroy() override {
        delete this;
       
        return true;
    };
    
private:
	baseProxy *proxy_;
    bool status_;

    baseFileWriter* writer_ = nullptr;
    
    std::string data_dir;
    std::string file_prefix;
    std::string file_suffix;

	std::string writer_key_l_;
	std::string writer_key_r_;
	std::string host_l_;


    std::string writer_key_;


	std::string create_writer_key(char side) {
        
        if(! proxy_ ) {
            return "";
        }
        
        std::string lh;
        if(! proxy_->ls().empty()) {
            lh = proxy_->ls().at(0)->host();
        }
        else {
            if(! proxy_->lda().empty()) {
                lh = proxy_->lda().at(0)->host();
            }
        }

        std::string l;
        if(! proxy_->ls().empty() ) {
            l = proxy_->ls().at(0)->name();
        }
        else {
            if(! proxy_->lda().empty()) {
                l = proxy_->lda().at(0)->name();
            }
        }

        std::string r;
        if(! proxy_->rs().empty()) {
            r = proxy_->rs().at(0)->name();
        }
        else {
            if( ! proxy_->rda().empty()) {
                r = proxy_->rda().at(0)->name();
            }
        }

        if (proxy_->lsize() > 0) {
            host_l_ = lh;
        }
        
        if (side == 'L' || side == 'l') {
			
			if (proxy_->lsize() > 0 && proxy_->rsize() > 0 ) {
				return string_format("%s-%s",l.c_str(),r.c_str());
			}
			else if (proxy_->lsize() > 0) {
				return string_format("%s-%s",l.c_str(),"unknown");
			} 
			else if (proxy_->rsize() > 0) {
				return string_format("%s-%s","unknown",r.c_str());
			} 
			else {
				return std::string("unknown-unknown");
			}
		} else {
			if (proxy_->lsize() > 0 && proxy_->rsize() > 0 ) {
				return string_format("%s-%s",r.c_str(),l.c_str());
			}
			else if (proxy_->rsize() > 0) {
				return string_format("%s-%s",r.c_str(),"unknown");
			} 
			else if (proxy_->lsize() > 0) {
				return string_format("%s-%s","unknown",l.c_str());
			} 
			else {
				return std::string("unknown-unknown");
			}
		}
	}
	
	std::string create_writer_key() {
        writer_key_l_ = create_writer_key('L');
        writer_key_r_ = create_writer_key('R');
        
        if(writer_key_l_.empty() || writer_key_r_.empty()) {
            return "";
        }
        
        mkdir(data_dir.c_str(),700);
            
        std::string hostdir = data_dir+"/"+host_l_+"/";
        mkdir(hostdir.c_str(),0770);

        time_t now = time(nullptr);
        tm loc{0};

        localtime_r(&now,&loc);

        std::string datedir = string_format("%d-%02d-%02d/", loc.tm_year+1900, loc.tm_mon+1, loc.tm_mday);
        mkdir((hostdir+datedir).c_str(),700);
        
        std::string file_datepart = string_format("%02d-%02d-%02d_", loc.tm_hour, loc.tm_min, loc.tm_sec);

        std::stringstream ss;
        
        ss << hostdir << datedir << file_prefix << file_datepart << writer_key_l_ << "." << file_suffix;
        writer_key_ = ss.str();

        return writer_key_;
    }


public:

	inline bool status() { return status_; }
    inline void status(bool b) { status_ = b; }

  
	void left_write(buffer const& b) {  write('L',b); };
	void right_write(buffer const& b) {  write('R',b); };
	
	void write(char side, buffer b) {
		if (side == 'l' || side == 'L') {
			left_write(hex_dump(b.data(),b.size(),0,'>'));
		} else {
			right_write(hex_dump(b.data(),b.size(),2,'<'));
		}
	}

	void left_write(std::string s) {  write('L',s); };
	void right_write(std::string s) {  write('R',s); };

	virtual void write(char side, std::string s) {
		
		timeval now{0};
		gettimeofday(&now, nullptr);
		char d[64];
		memset(d,0,64);
		ctime_r(&now.tv_sec,d);
		
		std::string& k1 = writer_key_l_;
		std::string& k2 = writer_key_r_;

		if (side == 'R' || side == 'r') {
			k1 = writer_key_r_;
			k2 = writer_key_l_;
		}
		
		if(status()) {

            if(! writer_->opened() ) {
                if (writer_->open(writer_key_)) {
                    DIA_("writer '%s' created",writer_key_l_.c_str());
                } else {
                    ERR_("write '%s' failed to open dump file!",writer_key_l_.c_str());
                }
            }
            
            if (writer_->opened()) {

                std::stringstream ss;
                ss << d << "+" << now.tv_usec << ": "<< k1 << "(" << k2 << ")\n";
                ss << s << '\n';

                writer_->write(writer_key_, ss.str());

            } else {
                ERRS_("cannot write to stream, writer not opened.");
            }
        }   
	}
	
	
    std::string to_string(int verbosity = iINF) override {
        return string_format("Traflog: file=%s opened=%d",writer_key_.c_str(),writer_->opened());
    }
	
    DECLARE_C_NAME("trafLog");
    DECLARE_LOGGING(to_string);	
};

}

#endif