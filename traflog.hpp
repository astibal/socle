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
#include <fstream>
#include <iostream>


template <class Com>
class trafLog {

public:
	trafLog(baseProxy<Com> *p) :
    proxy_(p),
	active_(false),
	writer_(NULL),
	writer_key_l_("???:???"),
	writer_key_r_("???:???") {
	}
	
	~trafLog() {
        writer_->close();
        delete writer_;
    }
  
private:
	baseProxy<Com> *proxy_;
	bool active_;
	std::ofstream *writer_;
	std::string writer_key_l_;
	std::string writer_key_r_;
	std::string host_l_;	
	
	
	std::string create_writer_key(char side) {
        std::string lh;
        if(proxy_->ls().size()) lh = proxy_->ls().at(0)->host();
        else if(proxy_->lda().size()) lh = proxy_->lda().at(0)->host();

        std::string l;
        if(proxy_->ls().size()) l = proxy_->ls().at(0)->name();
        else if(proxy_->lda().size()) l = proxy_->lda().at(0)->name();

        std::string r;
        if(proxy_->rs().size()) r = proxy_->rs().at(0)->name();
        else if(proxy_->rda().size()) r = proxy_->rda().at(0)->name();

        if (proxy_->lsize() > 0) {
            host_l_ = lh.c_str();
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
	
	bool create_writer() {
		
		writer_key_l_ = create_writer_key('L');
		writer_key_r_ = create_writer_key('R');
		
		std::string datadir = "mitm/";
		mkdir(datadir.c_str(),700);
			
		std::string hostdir = datadir+host_l_+"/";
		mkdir(hostdir.c_str(),0770);

		time_t now = time(0);
		struct tm loc;
		localtime_r(&now,&loc);
		std::string datedir = string_format("%d-%02d-%02d/",loc.tm_year+1900,loc.tm_mon+1,loc.tm_mday);
		mkdir((hostdir+datedir).c_str(),700);
		
		std::string file_datepart = string_format("%02d-%02d-%02d_",loc.tm_hour,loc.tm_min,loc.tm_sec);
		
		writer_ = new std::ofstream(hostdir + datedir + "mitm_dump_" + file_datepart + writer_key_l_);
		if(writer_->is_open()) {
			active_ = true;
			return true;
		}
		
		active_ = false;
		delete writer_;
		return false;
	}
	

public:
	inline bool active() { return active_; }
	inline void active(bool b) { active_ = b; }
  
	void left_write(buffer b) {  write('L',b); };
	void right_write(buffer b) {  write('R',b); };
	
	void write(char side, buffer b) {
		if (side == 'l' || side == 'L') {
			left_write(hex_dump(b.data(),b.size(),0,'>'));
		} else {
			right_write(hex_dump(b.data(),b.size(),2,'<'));
		}
	}

	void left_write(std::string s) {  write('L',s); };
	void right_write(std::string s) {  write('R',s); };
	
	void write(char side, std::string s) {
		
		timeval now;
		gettimeofday(&now,NULL);
		char d[64];
		memset(d,0,64);
		ctime_r(&now.tv_sec,d);
		
		std::string& k1 = writer_key_l_;
		std::string& k2 = writer_key_r_;
		if (side == 'R' || side == 'r') {
			k1 = writer_key_r_;
			k2 = writer_key_l_;
		}
		
		if(! active()) {
			if (create_writer()) {
				DIA_("writer '%s' created",writer_key_l_.c_str());
			} else {
				ERR_("write '%s' creation failed!",writer_key_l_.c_str());
			}
		}
		
		if (active()) {
			
			*writer_ << d << "+" << now.tv_usec << ": "<< k1 << "(" << k2 << ")\n";
			*writer_ << s << '\n';
		}
	}
};

#endif