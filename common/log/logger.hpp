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


#ifndef LOGGER_HPP
#define LOGGER_HPP

#include <cstring>
#include <iostream>
#include <ctime>

#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include <map>
#include <set>
#include <functional>
#include <algorithm>
#include <iomanip>

#include <log/loggermac.hpp>
#include <log/loglevel.hpp>

#include <display.hpp>
#include <stringformat.hpp>



std::string ESC_ (const std::string &s);

#define ESC(x) ESC_(x).c_str()

struct timer {
    time_t last;
    unsigned int timeout;
};

typedef struct timer timer_tt;

struct logger_profile_syslog {
    int facility = 23; // local7
    int severity = 6;  // information;
    
    inline int prival() const { return facility * 8 + ( (severity > DEB) ? DEB.level() : severity ); };
};


class logger_profile {

public:  
    typedef enum { FILE=0, REMOTE_RAW=1, REMOTE_SYSLOG=3 } logger_type_t;
    logger_type_t logger_type = FILE;
    
    logger_profile_syslog syslog_settings;
    
    virtual ~logger_profile();    
    loglevel level_ = INF;
    unsigned int period_ = 5;
    time_t last_period = 0;
    bool last_period_status = false;
    
    //if target is set, should we write also to std::cout?
    bool dup_to_cout_ = true;
    
    //should we print also source with line, if loglevel >= DIA?
    bool print_srcline_ = true;

    //should we print it always, regarless of log level?
    bool print_srcline_always_ = false;


    // where to log?
    std::list<std::ostream*> targets_;
    std::list<int> remote_targets_;
};

// inherit default setting from logger_profile
class logger : public logger_profile {
protected:

    mutable std::recursive_mutex mtx_lout;
    std::map<std::string,timer_tt> timers;
    mutable std::mutex mtx_timers;


    std::map<uint64_t,logger_profile*> target_profiles_;
    std::map<uint64_t,std::string> target_names_;

public:
    logger() { level_=NON; period_ =5; target_names_[0]="unknown";};
    virtual ~logger() {};

    inline void level(loglevel l) { level_ = l; };
    inline loglevel level(void) const { return level_; };

    inline void dup2_cout(bool b) { dup_to_cout_ = b; }
    inline bool dup2_cout() { return dup_to_cout_; }

    inline void print_srcline(bool b) { print_srcline_ = b; }
    inline bool& print_srcline() { return print_srcline_; }
    inline void print_srcline_always(bool b) { print_srcline_always_ = b; }
    inline bool& print_srcline_always() { return print_srcline_always_; }

    bool click_timer (const std::string &xname, int interval);


    std::list<std::ostream*>& targets() { return targets_; }
    void targets(std::string name, std::ostream* o) { targets_.push_back(o); target_names_[(uint64_t)o] = name; }

    std::list<int>& remote_targets() { return remote_targets_; }
    void remote_targets(std::string name, int s) { remote_targets_.push_back(s); target_names_[s] = name; }

    virtual int write_log(loglevel level, std::string& sss);

    bool should_log_topic(loglevel& writer, loglevel& msg);

    template <class ... Args>
    void log(loglevel l, const std::string& fmt, Args ... args);
    //void log_w_name(loglevel l, const char* n, const std::string& fmt, ...);

    template <class ... Args>
    void log_w_name(loglevel l, std::string n, const std::string& fmt, Args ... args);

    template <class ... Args>
    void log2(loglevel l, const char* f, int li, const std::string& fmt, Args ... args);
    //void log2_w_name(loglevel l, const char* f, int li, const char* n, const std::string& fmt, ...);

    template <class ... Args>
    void log2_w_name(loglevel l, const char* f, int li, std::string n, const std::string& fmt, Args ... args);

    std::map<uint64_t,logger_profile*>& target_profiles() { return target_profiles_; }
    std::map<uint64_t,std::string>& target_names() { return target_names_; }
    const char* target_name(uint64_t k) {
        auto it = target_names().find(k);
        if(it != target_names().end()) {
            std::string& r = target_names()[k];
            return r.c_str();
        }
        else return target_name(0);
    }

    inline unsigned int period() { return period_; }
    inline void period(unsigned int p) { period_ = p; }

    bool periodic_start(unsigned int s);
    bool periodic_end();

    // any change in target profiles could imply adjusting internal logging level.
    // For example: having internal level set to 5 (NOTify), so is the file logging level.
    // Someone adds syslog and remote raw loggers, one from them set to 6 (INF).
    // Unless we change internal logging level, he will not see on remotes any INF messages, because
    // internal logging level prohibits processing of INF level, writer receives only NOT.
    // This methods interates through targets and sets logging level to highest level used by targets.
    // @return log level difference, therefore negative if we decreased logging level, zero if unchanged,
    // positive if log level is raised.
    loglevel adjust_level();
};


extern logger* lout_;

extern logger* get_logger();
extern logger* create_default_logger();
extern void set_logger(logger*);

static const std::string level_table[] = {"None    ","Fatal   ","Critical","Error   ","Warning ","Notify  ",
                                          "Informat","Diagnose","Debug   ","Dumpit  ","Extreme "};

#pragma GCC diagnostic ignored "-Wformat-security"
#pragma GCC diagnostic push

template <class ... Args>
void logger::log(loglevel l, const std::string& fmt,  Args ... args) {


    auto now = std::chrono::system_clock::now();
    auto millisecs=
            std::chrono::duration_cast<std::chrono::milliseconds>(
                    now.time_since_epoch()
            );
  //auto seconds = millisecs.count()/1000;
    auto usec   = (millisecs.count()%1000)*1000;

    auto tt = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&tt);

    std::string str = string_format(fmt.c_str(), args...);


    std::string desc = std::string(level_table[0]);
    if (l > sizeof(level_table)-1) {
        desc = string_format("%d",l);
    } else {
        desc = level_table[l.level()];
    }


    std::stringstream ss;

    if(flag_test(l.flags(),LOG_FLRAW)) {
        ss << str;
    }
    else {
        ss << std::put_time(&tm, "%y-%m-%d %H:%M:%S") << "." << string_format("%06d", usec) << " <";
        ss << std::hex << std::this_thread::get_id() << "> " << desc << " - " << str;
    }


    std::string sss = ss.str();

    //std::lock_guard<std::recursive_mutex> lck(mtx_lout);

    write_log(l,sss);
};


template <class ... Args>
void logger::log2(loglevel l, const char* src, int line, const std::string& fmt, Args ... args ) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);

    std::string src_info = string_format("%20s:%-4d: ",src,line);

    std::string str = string_format(fmt.c_str(), args...);

    log(l,src_info + str);
}


template <class ... Args>
void logger::log_w_name(loglevel l, std::string name, const std::string& fmt, Args ... args) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);

    std::string  str = string_format(fmt.c_str(), args...);
    log(l,string_format("[%s]: ",name.c_str())+str);
}

template <class ... Args>
void logger::log2_w_name(loglevel l, const char* f, int li, std::string name, const std::string& fmt, Args ... args) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);

    std::string src_info = string_format("%20s:%-4d: ",f,li);
    std::string c_name = string_format("[%s]: ",name.c_str());

    std::string str = string_format(fmt.c_str(), args...);
    log(l,src_info+c_name+str);
};

#pragma GCC diagnostic pop


#endif // LOGGER_HPP
