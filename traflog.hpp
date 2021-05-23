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
#include <deque>
#include <queue>

#include <sobject.hpp>

namespace socle {


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

protected:
    explicit poolFileWriter(): ofstream_pool("ofstream-pool", 30, true ) {
        log = logan::create("socle.poolFileWriter");
    }

public:
    poolFileWriter& operator=(poolFileWriter const&) = delete;
    poolFileWriter(poolFileWriter const&) = delete;

    static poolFileWriter* instance() {
        static poolFileWriter w = poolFileWriter();
        return &w;
    }

    std::recursive_mutex& ofstream_lock() { return ofstream_pool.getlock(); }
    ptr_cache<std::string, std::ofstream>& ofstream_cache() { return ofstream_pool; };


    std::size_t write(std::string const& fnm, std::string const& str) override {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto o = get_ofstream(fnm);

        if(!o) return 0;

        o->flush();
        (*o) << str;


        auto sz = str.size();

        _dia("file: %s: written %dB", fnm.c_str(), sz);
        return sz;
    };

    std::shared_ptr<std::ofstream> get_ofstream(std::string const& fnm, bool create = true) {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto optr = ofstream_pool.get(fnm);
        if (! optr) {

            if(! create) {
                _dia("file: %s: stream not found.", fnm.c_str());
                return nullptr;
            }

            _dia("file: %s: creating a new stream", fnm.c_str());

            for(auto const& s: ofstream_pool.items()) {
                _deb("pool item: %s", s.c_str());
            }

            auto* stream = new std::ofstream(fnm , std::ofstream::out | std::ofstream::app);

            bool replaced = ofstream_pool.set(fnm, stream);
            _deb("new ostream %s -> 0x%x (replaced=%d)", fnm.c_str(), stream, replaced);

            auto entry = ofstream_pool.cache().find(fnm);
            if(entry != ofstream_pool.cache().end()) {

                auto exo = entry->second->ptr();
                _deb("new ofstream entry: 0x%x", exo.get());

            } else {

                _deb("cannot find inserted entry!!!");
            }


            return ofstream_pool.get(fnm);
        } else {
            _deb("file: %s: existing stream", fnm.c_str());
            return optr;
        }
    }

    bool flush(std::string const& fnm) override {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto o = get_ofstream(fnm, false);
        if(o) {
            o->flush();
            _dia("file: %s: flushed", fnm.c_str());
            return true;
        }

        return false;
    }

    bool close(std::string const& fnm) override {

        std::scoped_lock<std::recursive_mutex> l_(ofstream_pool.getlock());

        auto o = get_ofstream(fnm, false);
        if(o) {
            ofstream_pool.erase(fnm);

            _dia("file: %s: erased", fnm.c_str());
            return true;
        }

        return false;
    }

    // trafLog compatible API
    bool open(std::string const& fnm) override {

        auto o = get_ofstream(fnm);

        return o != nullptr;
    }

    // pool writer is always opened
    bool opened() override { return true; };

private:
    logan_lite log;

    // pool of opened streams. If expired, they will be closed and destruct.
    ptr_cache<std::string, std::ofstream> ofstream_pool;
};

class fileWriter : public baseFileWriter {

    std::unique_ptr<std::ofstream> writer_;
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

        writer_ = std::make_unique<std::ofstream>(fnm , std::ofstream::out | std::ofstream::app);
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


class threadedPoolFileWriter : public poolFileWriter {

    // map of log messages
    std::unordered_map<std::string, std::queue<std::string>> task_queue_;
    // files to handle - worker thread will remove file he works on from *task_files_* and ads it to *active_files*
    std::queue<std::string> task_files_;
    std::mutex queue_lock_;


    // worker thread controlling mutex.
    std::mutex workload_mutex_;

    explicit threadedPoolFileWriter() {
        log = logan::create("socle.threadedPoolFileWriter");

        // add 2 workers.
        add_worker();
        add_worker();
    }

    ~threadedPoolFileWriter() override {
        stop_signal_ = true;
        for( auto& t: threads_) {
            if(t.joinable())
                t.join();
        }
    }

    void add_worker() {
        auto t = std::thread(&threadedPoolFileWriter::worker, this);
        threads_.emplace_back(std::move(t));
    }

    void worker() {
        :: pthread_setname_np(pthread_self(), "sx-thwrt");
        while(! stop_signal_)
        {
            bool wait = false;
            std::string fnm;
            {
                std::scoped_lock<std::mutex> l_(queue_lock_);
                if (task_files_.empty()) {
                    wait = true;
                } else {
                    fnm = task_files_.front();
                    task_files_.pop();
                }
            }
            // we will wait if the queue was empty or handled by other workers
            if(wait || fnm.empty()) {
                ::usleep(1000);
            } else {
                // we work on 'fnm' file
                bool cont = true;
                do {
                    std::string msg;
                    {
                        // get the string
                        std::scoped_lock<std::mutex> l_(queue_lock_);

                        auto it = task_queue_.find(fnm);
                        if(it != task_queue_.end()) {
                            auto& myqueue = task_queue_[fnm];
                            if(! myqueue.empty()) {
                                msg = myqueue.front();
                                myqueue.pop();

                                // shortcut - if this was last element, dont continue
                                if(myqueue.empty()) {
                                    task_queue_.erase(fnm);
                                    cont = false;
                                }
                            } else {
                                // myqueue is empty
                                task_queue_.erase(fnm);
                                cont = false;
                            }

                        } else{
                            // fnm not it hash
                            cont = false;
                        }
                    }

                    // queue is now unlocked!!!
                    // OK - we get the string, let's write it to the stream
                    poolFileWriter::write(fnm, msg);

                } while(cont);
            }
        }
    }

    bool stop_signal_ = false;
    std::vector<std::thread> threads_;

    logan_lite log;
public:
    threadedPoolFileWriter& operator=(threadedPoolFileWriter const&) = delete;
    threadedPoolFileWriter(poolFileWriter const&) = delete;

    static threadedPoolFileWriter* instance() {
        static threadedPoolFileWriter w = threadedPoolFileWriter();
        return &w;
    }

    std::mutex& queue_lock() { return  queue_lock_; }
    std::unordered_map<std::string, std::queue<std::string>>& queue() { return task_queue_; };
    std::queue<std::string>& task_files()  { return task_files_; };


    // write won't actually write to file, but will queue that task
    size_t write(std::string const &fnm, std::string const &str) override {
        {
            // ad this file to tasks, but only if it's not already handled by worker
            std::scoped_lock<std::mutex> l_(queue_lock_);
            if(task_queue_.find(fnm) == task_queue_.end()) {
                task_files_.push(fnm);
            }
            task_queue_[fnm].push(str);
        }

        // we enqueued it, just returning its size
        return str.size();
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
	
    DECLARE_C_NAME("trafLog")
    DECLARE_LOGGING(to_string)
};

}

#endif