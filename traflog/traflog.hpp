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

#ifndef TRAFLOG_HPP
#define TRAFLOG_HPP

#include <traflog/threadedpoolwriter.hpp>
#include <traflog/filewriter.hpp>
#include <baseproxy.hpp>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fstream>
#include <iostream>
#include <deque>
#include <queue>

#include <sobject.hpp>

namespace socle {

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
            writer_ = threadedPoolFileWriter::instance();
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
        
        mkdir(data_dir.c_str(),0750);
            
        std::string hostdir = data_dir+"/"+host_l_+"/";
        mkdir(hostdir.c_str(),0750);

        time_t now = time(nullptr);
        tm loc{};

        localtime_r(&now,&loc);

        std::string datedir = string_format("%d-%02d-%02d/", loc.tm_year+1900, loc.tm_mon+1, loc.tm_mday);
        mkdir((hostdir+datedir).c_str(),0750);
        
        std::string file_datepart = string_format("%02d-%02d-%02d_", loc.tm_hour, loc.tm_min, loc.tm_sec);

        std::stringstream ss;
        
        ss << hostdir << datedir << file_prefix << file_datepart << writer_key_l_ << "." << file_suffix;
        writer_key_ = ss.str();

        return writer_key_;
    }


public:

	inline bool status() const { return status_; }
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

	void left_write(std::string const& s) {  write('L', s); };
	void right_write(std::string const& s) {  write('R', s); };

	virtual void write(char side, std::string const& s) {
		
		timeval now{};
		gettimeofday(&now, nullptr);
		char d[64];
		memset(d,0,64);
		ctime_r(&now.tv_sec,d);
		
		std::string k1;
		std::string k2;

		if (side == 'R' || side == 'r') {
			k1 = writer_key_r_;
			k2 = writer_key_l_;
		} else {
            k1 = writer_key_l_;
            k2 = writer_key_r_;
		}
		
		if(status()) {

            if(! writer_->opened() ) {
                if (writer_->open(writer_key_)) {
                    _dia("writer '%s' created",writer_key_l_.c_str());
                } else {
                    _err("write '%s' failed to open dump file!",writer_key_l_.c_str());
                }
            }
            
            if (writer_->opened()) {

                std::stringstream ss;
                ss << d << "+" << now.tv_usec << ": "<< k1 << "(" << k2 << ")\n";
                ss << s << '\n';

                writer_->write(writer_key_, ss.str());

            } else {
                _err("cannot write to stream, writer not opened.");
            }
        }   
	}
	
	
    std::string to_string(int verbosity) const override {
        return string_format("Traflog: file=%s opened=%d",writer_key_.c_str(),writer_->opened());
    }
	
    TYPENAME_OVERRIDE("trafLog")
    DECLARE_LOGGING(to_string)
};

}

#endif