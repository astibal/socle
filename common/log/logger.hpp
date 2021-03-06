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
#include <memory>

#include <log/loggermac.hpp>
#include <log/loglevel.hpp>

#include <display.hpp>
#include <stringformat.hpp>

using namespace socle;


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
    
    inline int prival() const { return facility * 8 + ( (severity > log::level::DEB) ? log::level::DEB.level() : severity ); };
};


class logger_profile {

public:

    [[maybe_unused]]
    typedef enum { FILE=0, REMOTE_RAW=1, REMOTE_SYSLOG=3 } logger_type_t;
    logger_type_t logger_type = FILE;
    
    logger_profile_syslog syslog_settings;
    
    virtual ~logger_profile();    
    loglevel level_ = log::level::INF;
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

    using ostream_list_t = std::list<std::pair<std::unique_ptr<std::ostream>, std::unique_ptr<std::mutex>>>;
    ostream_list_t targets_;

    using fd_list_t = std::list<std::pair<int, std::mutex*>>;
    fd_list_t remote_targets_;
};

class Log;

// inherit default setting from logger_profile
class LogMux : public logger_profile {
protected:

    mutable std::recursive_mutex mtx_lout;
    std::map<std::string,timer_tt> timers;
    mutable std::mutex mtx_timers;


    std::map<uint64_t,std::unique_ptr<logger_profile>> target_profiles_;
    std::map<uint64_t,std::string> target_names_;

    friend class Log;
    LogMux() { level_= log::level::NON; period_ =5; target_names_[0]="unknown";};
public:
    ~LogMux() override = default;

    inline void level(loglevel const& l) { level_ = l; };
    inline loglevel level() const { return level_; };

    inline void dup2_cout(bool b) { dup_to_cout_ = b; }
    inline bool dup2_cout() { return dup_to_cout_; }

    inline void print_srcline(bool b) { print_srcline_ = b; }
    inline bool& print_srcline() { return print_srcline_; }
    inline void print_srcline_always(bool b) { print_srcline_always_ = b; }
    inline bool& print_srcline_always() { return print_srcline_always_; }

    bool click_timer (const std::string &xname, int interval);


    logger_profile::ostream_list_t& targets() { return targets_; }
    void targets(std::string name, std::ostream* o) { targets_.emplace_back(o, new std::mutex()); target_names_[(uint64_t)o] = name; }

    logger_profile::fd_list_t& remote_targets() { return remote_targets_; }
    void remote_targets(std::string name, int s) { remote_targets_.emplace_back(s, new std::mutex()); target_names_[s] = name; }

    virtual size_t write_log(loglevel level, std::string& sss);

    bool should_log_topic(loglevel& writer, loglevel& msg);

    template <class ... Args>
    void log_simple(const char* str);

    template <class ... Args>
    void log_simple(std::stringstream& ss);

    template <class ... Args>
    void log(loglevel const& l, const std::string& fmt, Args ... args);
    //void log_w_name(loglevel l, const char* n, const std::string& fmt, ...);

    template <class ... Args>
    void log_w_name(loglevel const& l, std::string n, const std::string& fmt, Args ... args);

    template <class ... Args>
    void log2(loglevel const& l, const char* f, int li, const std::string& fmt, Args ... args);
    //void log2_w_name(loglevel l, const char* f, int li, const char* n, const std::string& fmt, ...);

    template <class ... Args>
    void log2_w_name(loglevel const& l, const char* f, int li, std::string n, const std::string& fmt, Args ... args);

    auto& target_profiles() { return target_profiles_; }
    std::map<uint64_t,std::string>& target_names() { return target_names_; }
    const char* target_name(uint64_t k) {
        auto it = target_names().find(k);
        if(it != target_names().end()) {
            std::string& r = target_names()[k];
            return r.c_str();
        }
        else return target_name(0);
    }

    [[maybe_unused]] inline unsigned int period() { return period_; }
    [[maybe_unused]] inline void period(unsigned int p) { period_ = p; }

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
     [[deprecated("internal logging level is not used anymore")]]
     [[maybe_unused]]
     loglevel adjust_level();
};



class Log {

public:
    static std::shared_ptr<LogMux> default_logger ();

    static std::shared_ptr<Log> instance() { return self; }
    static std::shared_ptr<LogMux> get();
    static void set(std::shared_ptr<LogMux> l);

    static inline const std::string levels[] = {"None    ", "Fatal   ", "Critical", "Error   ", "Warning ", "Notify  ",
                                                "Informat", "Diagnose", "Debug   ", "Dumpit  ", "Extreme "};

    static void init() { self = std::make_shared<Log>(); }
    Log() : lout_(default_logger()) {};
private:

    std::shared_ptr<LogMux> lout_;
    static inline std::shared_ptr<Log> self;
};

template <class ... Args>
void LogMux::log_simple(const char* str) {
    std::cerr << str << std::endl;
}

template <class ... Args>
void LogMux::log_simple(std::stringstream& ss) {
    std::string s = ss.str();
    ss.clear();

    std::cerr << s << std::endl;
}

template <class ... Args>
void LogMux::log(loglevel const& l, const std::string& fmt, Args ... args) {


    auto now = std::chrono::system_clock::now();
    auto usec_total=
            std::chrono::duration_cast<std::chrono::microseconds>(
                    now.time_since_epoch()
            );
  
    auto usec   = (usec_total.count() % (1000 * 1000));
    std::tm tm{};

#ifndef _POSIX_C_SOURCE
    auto tt = std::chrono::system_clock::to_time_t(now);
#else
    time_t tt = time(nullptr);
#endif


    // protect thread-unsafe function  (it returns pointer to its internal state)
    auto get_tm = [&tt, &tm]() -> std::tm const& {
#ifndef _POSIX_C_SOURCE
        static std::mutex m;
        auto l_ = std::scoped_lock(m);
        tm = *std::localtime(&tt);

        return tm;
#else
        struct tm time_result{};
        auto* r = localtime_r(&tt, &time_result);
        tm.tm_hour = r->tm_hour;
        tm.tm_min = r->tm_min;
        tm.tm_sec = r->tm_sec;
        tm.tm_year = r->tm_year;
        tm.tm_mon = r->tm_mon;
        tm.tm_mday = r->tm_mday;

        return tm;
#endif
    };

    std::string str = string_format(fmt.c_str(), args...);


    std::string desc = std::string(Log::levels[0]);

    if (l > sizeof(Log::Log::levels) - 1) {
        desc = string_format("%d", l.level());
    } else {
        desc = Log::levels[l.level()];
    }


    std::stringstream ss;

    if(flag_test(l.flags(),LOG_FLRAW)) {
        ss << str;
    }
    else {
        auto tm = get_tm();
        ss << std::put_time( &tm, "%y-%m-%d %H:%M:%S") << "." << string_format("%06d", usec) << " <";
        ss << std::hex << std::this_thread::get_id() << "> " << desc << " - " << str;
    }


    std::string sss = ss.str();

    //std::lock_guard<std::recursive_mutex> lck(mtx_lout);

    write_log(l,sss);
}


template <class ... Args>
void LogMux::log2(loglevel const& l, const char* src, int line, const std::string& fmt, Args ... args ) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);

    std::string src_info = string_format("%20s:%-4d: ",src,line);

    std::string str = string_format(fmt.c_str(), args...);

    log(l,src_info + str);
}


template <class ... Args>
void LogMux::log_w_name(loglevel const& l, std::string name, const std::string& fmt, Args ... args) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);

    std::string  str = string_format(fmt.c_str(), args...);
    log(l,string_format("[%s]: ",name.c_str())+str);
}

template <class ... Args>
void LogMux::log2_w_name(loglevel const&  l, const char* f, int li, std::string name, const std::string& fmt, Args ... args) {

    std::lock_guard<std::recursive_mutex> lck(mtx_lout);

    std::string src_info = string_format("%20s:%-4d: ",f,li);
    std::string c_name = string_format("[%s]: ",name.c_str());

    std::string str = string_format(fmt.c_str(), args...);
    log(l,src_info+c_name+str);
}

#endif // LOGGER_HPP
