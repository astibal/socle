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

#include <iostream>
#include <string>
#include <mutex>
#include <memory>

#include <log/logger.hpp>
#include <sys/socket.h>


std::shared_ptr<LogMux> Log::get() {
    return instance()->lout_;
}

std::shared_ptr<LogMux> Log::default_logger() {
    static auto r = std::shared_ptr<LogMux>(new LogMux);
    return r;
}

void Log::set(std::shared_ptr<LogMux> l) {
    instance()->lout_ = l;
}


std::string ESC_ (const std::string &s) {
    std::string t = s;
    std::replace( t.begin(), t.end(), '%', '^');
    return t;
}

logger_profile::~logger_profile() { 
    for(auto& [ optr, mptr ]: targets_) {
        if(optr) {
            optr->flush();
        }
    }
}

bool LogMux::periodic_start(unsigned int s) {
	auto now = static_cast<unsigned long>(time(nullptr));

    last_period_status = now > static_cast<unsigned long>(last_period) + s;

	return last_period_status;
}


bool LogMux::periodic_end() {
	if (last_period_status) {
		time_t now = time(nullptr);
		last_period = now;
		
		return true;
	}
	
	return false;
}


bool LogMux::should_log_topic(loglevel& writer, loglevel& msg) {

    // writer loglevel
    unsigned int t = writer.topic();
    
    // if msg has set topic, we need to check what to do
    if(msg.topic() != 0) {
        if(msg.more() != nullptr) {
            if(msg.more()->exclusive_exact) {
                if(t != msg.topic()) {
                    return false;
                }
            }
            
            // Exclusive topic
            if (msg.more()->exclusive_topic) {
                if(t == iNON) return false;
                
                unsigned int l_area = 0xffff0000 | msg.topic();
                unsigned int t_area = 0xffff0000 | t;
                if(l_area != t_area) {
                    return false;
                }
            }
        }
    } else {
        // msg doesn't have any topic (== 0)
        if(t > 0) {
            
            // we don't want to write generic messages into specialized writer
            return false;
        }
    }
    
    return true;
}

size_t LogMux::write_log(loglevel level, std::string& sss) {

    bool really_dup = dup2_cout();

    // targets are ostream pointers
    for( auto const& [ target, mut ] : targets()) {


        if(target_profiles().find((uint64_t) target.get()) != target_profiles().end()) {
            if(target_profiles()[(uint64_t)  target.get()]->level_ < level) { continue; }
        }
        
        if (!should_log_topic(target_profiles()[(uint64_t) target.get()]->level_,level)) continue;

        auto l_ = std::scoped_lock(*mut);
        *target << sss << std::endl;
    }

    for(auto [ rem_target, mut ]: remote_targets()) {
        
        if(target_profiles().find((uint64_t) rem_target) != target_profiles().end()) {
            if(target_profiles()[(uint64_t) rem_target]->level_ < level ) { continue; }
        }
        
        if (!should_log_topic(target_profiles()[(uint64_t) rem_target]->level_,level)) continue;
            
        std::stringstream  s;

        // prefixes
        if(target_profiles()[(uint64_t) rem_target]->logger_type == REMOTE_SYSLOG) {
            s <<  string_format("<%d> ",target_profiles()[(uint64_t) rem_target]->syslog_settings.prival());
        } 
        
        s << sss ;
        
        // suffixes
        if(target_profiles()[(uint64_t) rem_target]->logger_type != REMOTE_SYSLOG) {
            s <<  "\r\n";
        } 
        
        std::string a = s.str();

        auto l_ = std::scoped_lock(*mut);
        if(::send(rem_target, a.c_str(),a.size(),0) < 0) {
            std::cerr << string_format("logger::write_log: cannot write remote socket: %d", rem_target);
        }
        
        //if(target_profiles()[(uint64_t)*i]->dup_to_cout_) really_dup = true;
    }


    if(level <= level_) {
        // if set, log extra to stdout/stderr
        if (really_dup) {
            std::ostream *o = &std::cout;

            if (level <= log::level::ERR) {
                o = &std::cerr;
            }
            *o << sss << std::endl;
        }
    }
    return sss.size();
}



bool LogMux::click_timer (const std::string &xname, int interval) {
	
	std::lock_guard<std::mutex> lck(mtx_timers);
	
	std::string name;
	auto myid = std::this_thread::get_id();
	std::stringstream ss;
	ss << myid;

	name += xname + "_th" + ss.str();
	
	auto r = timers.find(name);
	if (r != timers.end()) {
		// we found entry
		time_t l = r->second.last;
		int i = r->second.timeout;
		
		time_t now = ::time(nullptr);
		
		if( now > l + i) {
			(*r).second.last = now;
			return true;
		} 
		else {
			return false;
		}
	
	} else {
		// we should establish a new timer
		time_t now = ::time(nullptr);
		timer_tt tt;
		tt.last = now;
		tt.timeout = interval;
		
		timers[name] = tt;
		
		return true;
	}
}

// DEPRECATED: we don't need adjusting internal logging based on profiles anymore.
[[maybe_unused]]
loglevel LogMux::adjust_level() {

    loglevel curr_level = level();
    loglevel max_common_level = log::level::NON;
    
    for( auto const& [ rem_target, mut ]: remote_targets() ) {
        loglevel this_level = target_profiles()[(uint64_t)rem_target]->level_;
        if ( this_level > max_common_level ) {
            max_common_level = this_level;
        }
    }
    for(auto const& [ optr, mut ]: targets()) {
        loglevel this_level = target_profiles()[(uint64_t)optr.get()]->level_;
        if ( this_level > max_common_level ) {
            max_common_level = this_level;
        }
    }
    
    // if we detect necessity
    if(max_common_level != curr_level) {
        level(max_common_level);
    } 
    
    // return log level difference, therefore negative if we decreased logging level, zero if unchanged, positive if log level is raised.
    return max_common_level - curr_level;
}



