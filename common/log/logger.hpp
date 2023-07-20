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
#include <deque>
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

struct timer_tt {
    time_t last;
    unsigned int timeout;
};

struct logger_profile_syslog {

    int facility = 23; // local7
    int severity = 6;  // information level

    inline int prival() const { return facility * 8 + ( (severity > log::level::DEB) ? log::level::DEB.level() : severity ); };
};


class logger_profile {

public:

    enum logger_type_t { FILE=0, REMOTE_RAW=1, REMOTE_SYSLOG=3 };
    logger_type_t logger_type = FILE;

    logger_profile_syslog syslog_settings;

    virtual ~logger_profile();
    loglevel level_ = socle::log::level::INF;
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

    using fd_list_t = std::list<std::pair<int, std::unique_ptr<std::mutex>>>;
    fd_list_t remote_targets_;
};

class Log;
std::tm get_tm(time_t const& tt);
unsigned long get_usec();

struct Events {
    mutable std::mutex events_lock_;

    // eventID,string - eventID can be used to store more details
    using event_queue_t = std::deque<std::pair<uint64_t, std::string>>;
    static inline size_t events_max_ = 1000;

    using event_detail_db_t = std::unordered_map<uint64_t, std::string>;

    // global eventid counter
    static inline uint64_t event_count_ = 100L;
    // if nonzero, current thread uses this exact eid. Use it instead of increment of global counter
    static inline thread_local uint64_t current_event_id_ = 0L;

    void clear() {
        auto lc_ = std::scoped_lock(events_lock_);
        events_.clear();
        event_detail_db_.clear();
    }
    event_queue_t const& entries() const { return events_; }
    std::mutex& events_lock() const { return events_lock_; };
    template <class ... Args>
    uint64_t insert(loglevel const& l, const std::string& fmt, Args ... args);
    template <class ... Args>
    uint64_t detail(uint64_t eid, const char* fmt, Args ... args);
    static uint64_t lock_event_id() { if(current_event_id_ > 0L) { return current_event_id_; } current_event_id_ = ++event_count_; return current_event_id_; }
    static void release_event_id() { current_event_id_ = 0L; }

    struct event_id_block {
        event_id_block() = default;
        event_id_block(event_id_block const&) = default;

        uint64_t eid = lock_event_id();
        ~event_id_block() { release_event_id(); }
    };

    [[nodiscard]] event_id_block event_block() { event_id_block r; return r; }
    auto& event_details() { return event_detail_db_; }

private:
    event_detail_db_t event_detail_db_;
    event_queue_t events_; // events ring buffer
};

// inherit default setting from logger_profile
class LogMux : public logger_profile {

    mutable std::recursive_mutex mtx_lout;
    std::map<std::string,timer_tt, std::less<>> timers;
    mutable std::mutex mtx_timers;


    std::map<uint64_t,std::unique_ptr<logger_profile>> target_profiles_;
    std::map<uint64_t,std::string> target_names_;

    Events events_;
public:
    LogMux() { level_= log::level::NON; period_ =5; target_names_[0]="unknown";};
    ~LogMux() override = default;

    inline void level(loglevel const& l) { level_ = l; };
    inline loglevel level() const { return level_; };

    inline void dup2_cout(bool b) { dup_to_cout_ = b; }
    inline bool dup2_cout() const { return dup_to_cout_; }

    inline void print_srcline(bool b) { print_srcline_ = b; }
    inline bool& print_srcline() { return print_srcline_; }
    inline void print_srcline_always(bool b) { print_srcline_always_ = b; }
    inline bool& print_srcline_always() { return print_srcline_always_; }

    bool click_timer (const std::string &xname, int interval);

    logger_profile::ostream_list_t& targets() { return targets_; }
    void targets(std::string_view name, std::ostream* o) { targets_.emplace_back(o, new std::mutex()); target_names_[(uint64_t)o] = name; }

    logger_profile::fd_list_t& remote_targets() { return remote_targets_; }
    void remote_targets(std::string_view name, int s) { remote_targets_.emplace_back(s, new std::mutex()); target_names_[s] = name; }

    virtual size_t write_log(loglevel level, std::string& sss);

    bool should_log_topic(loglevel& writer, loglevel& msg);

    template <class ... Args>
    void log_simple(const char* str) const;

    template <class ... Args>
    void log_simple(std::stringstream& ss) const;

    template <class ... Args>
    void log(loglevel const& l, const std::string& fmt, Args ... args);

    auto& target_profiles() { return target_profiles_; }
    std::map<uint64_t,std::string>& target_names() { return target_names_; }
    const char* target_name(uint64_t k) {
        auto it = target_names().find(k);
        if(it != target_names().end()) {
            std::string const& r = target_names()[k];
            return r.c_str();
        }
        else return target_name(0);
    }

    [[maybe_unused]] inline unsigned int period() const { return period_; }
    [[maybe_unused]] inline void period(unsigned int p) { period_ = p; }

    bool periodic_start(unsigned int s);
    bool periodic_end();

    Events& events() { return events_; }
};

class Log {

public:
    static std::shared_ptr<LogMux> default_logger ();

    static std::shared_ptr<Log> instance() { return self; }
    static std::shared_ptr<LogMux> get();
    static void set(std::shared_ptr<LogMux> l);

    static inline std::array<const char*,11> levels = {"None    ",
                                                       "Fatal   ",
                                                       "Critical",
                                                       "Error   ",
                                                       "Warning ",
                                                       "Notify  ",
                                                       "Informat",
                                                       "Diagnose",
                                                       "Debug   ",
                                                       "Dumpit  ",
                                                       "Extreme "};

    static std::string level_name(unsigned int l);
    static void init() { self = std::make_shared<Log>(); }

private:

    std::shared_ptr<LogMux> lout_ = default_logger();
    static inline std::shared_ptr<Log> self;
};

template <class ... Args>
void LogMux::log_simple(const char* str) const {
    std::cerr << str << std::endl;
}

template <class ... Args>
void LogMux::log_simple(std::stringstream& ss) const {
    std::string const s = ss.str();
    ss.clear();

    std::cerr << s << std::endl;
}


template <class ... Args>
uint64_t Events::insert(loglevel const& l, const std::string& fmt, Args ... args) {
    std::stringstream ss;

    if(not flag_test(l.flags(),LOG_FLRAW)) {
        time_t const tt = time(nullptr);
        auto tm = get_tm(tt);
        ss << std::put_time(&tm, "%y-%m-%d %H:%M:%S") << "." << string_format("%06d", get_usec()) << ": ";
        ss << Log::level_name(l.level()) << ": ";
    }
    ss << string_format(fmt.c_str(), args...);

    auto lc_ = std::scoped_lock(events_lock_);

    auto use_eid = current_event_id_ > 0L ? current_event_id_ : ++event_count_;

    events_.emplace_back( use_eid, ss.str());

    if(events_.size() > events_max_) {

        auto eid = events_.front().first;
        events_.pop_front();

        const auto it = event_detail_db_.find(eid);
        if(it != event_detail_db_.end()) event_detail_db_.erase(it);
    }

    return use_eid;
}

template <class ... Args>
uint64_t Events::detail(uint64_t eid, const char* fmt, Args ... args) {
    auto lc_ = std::scoped_lock(events_lock_);
    event_detail_db_.emplace(eid, string_format(fmt, args...));

    return eid;
}

template <class ... Args>
void LogMux::log(loglevel const& l, const std::string& fmt, Args ... args) {

    auto usec = get_usec();

#ifndef _POSIX_C_SOURCE
    auto tt = std::chrono::system_clock::to_time_t(now);
#else
    time_t const tt = time(nullptr);
#endif

    std::string str = string_format(fmt.c_str(), args...);
    auto desc = Log::level_name(l.level());

    std::stringstream ss;

    if(flag_test(l.flags(),LOG_FLRAW)) {
        ss << str;
    }
    else {
        auto timestamp = get_tm(tt);
        ss << std::put_time(&timestamp, "%y-%m-%d %H:%M:%S") << "." << string_format("%06d", usec) << " <";
        ss << std::hex << std::this_thread::get_id() << "> " << desc << " - " << str;
    }

    auto sss = ss.str();
    write_log(l, sss);
}

#endif // LOGGER_HPP
