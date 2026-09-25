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

#ifndef LOGAN_HPP
#define LOGAN_HPP

#include <string>
#include <log/loglevel.hpp>
#include <log/logger.hpp>
#include <mpstd.hpp>
#include <utility>
#include <shared_mutex>

#include <vars.hpp>

using namespace log::level;


#ifdef BUILD_RELEASE
#define  xext(x)  if(false) (x).ext
#define  xdum(x)  if(false) (x).dum
#else
#define  xext(x)  if(*(x).level() >= EXT) (x).ext
#define  xdum(x)  if(*(x).level() >= DUM) (x).dum
#endif
#define  xdeb(x)  if(*(x).level() >= DEB) (x).deb
#define  xdia(x)  if(*(x).level() >= DIA) (x).dia
#define  xinf(x)  if(*(x).level() >= INF) (x).inf
#define  xnot(x)  if(*(x).level() >= NOT) (x).noti
#define  xwar(x)  if(*(x).level() >= WAR) (x).war
#define  xerr(x)  if(*(x).level() >= ERR) (x).err
#define  xcri(x)  if(*(x).level() >= CRI) (x).cri
#define  xfat(x)  if(*(x).level() >= FAT) (x).fat

#define  _if_level(lev)  if(*log.level() >= (lev))

#ifdef BUILD_RELEASE
#define  _ext  if(false) log.ext
#define  _dum  if(false) log.dum
#define  _deb  if(false) log.deb
#define  _if_ext  if(false)
#define  _if_dum  if(false)
#define  _if_deb  if(false)
#else
#define  _ext  if(*log.level() >= EXT) log.ext
#define  _if_ext  if(*log.level() >= EXT)

#define  _dum  if(*log.level() >= DUM) log.dum
#define  _if_dum  if(*log.level() >= DUM)

#define  _deb  if(*log.level() >= DEB) log.deb
#define  _if_deb  if(*log.level() >= DEB)
#endif
#define  _dia  if(*log.level() >= DIA) log.dia
#define  _if_dia  if(*log.level() >= DIA)

#define  _inf  if(*log.level() >= INF) log.inf
#define  _if_inf  if(*log.level() >= INF)

#define  _not  if(*log.level() >= NOT) log.noti
#define  _if_not  if(*log.level() >= NOT)

#define  _war  if(*log.level() >= WAR) log.war
#define  _if_war  if(*log.level() >= WAR)

#define  _err  if(*log.level() >= ERR) log.err
#define  _if_err  if(*log.level() >= ERR)

#define  _cri  if(*log.level() >= CRI) log.cri
#define  _if_cri  if(*log.level() >= CRI)

#define  _fat  if(*log.level() >= FAT) log.fat
#define  _if_fat  if(*log.level() >= FAT)

#define  _cons  Log::get()->log_simple

class baseLoganMate {
public:
    [[nodiscard]] virtual  std::string& class_name() const = 0;
    [[nodiscard]] virtual std::string hr() const = 0;
    virtual ~baseLoganMate() = default;
};

class LoganMate : public baseLoganMate {
private:
    // this object logging
    loglevel  this_log_level_{NON};

public:
    // class-level logging
    static loglevel& log_level_ref() { static loglevel class_loglevel(iNON); return class_loglevel; }
    // this object logging
    loglevel& this_log_level_ref() { return this_log_level_; };

    [[nodiscard]] loglevel get_this_log_level() const { return this_log_level_ > log_level_ref() ? this_log_level_: log_level_ref() ; };
    void set_this_log_level(loglevel const& nl) { this_log_level_ = nl; };
};

class logan;

class logan_lite {

private:
    mutable std::shared_mutex lock_;
    // logging name in catalogue
    std::string topic_;

    // logging message prefix in log line
    static thread_local inline std::string context_ {};

    struct ContextFilter {
        ContextFilter() { active_.store(false); }

        std::atomic_bool active_{false};
        std::string value_{};
        static inline std::shared_mutex lock_{};

        void set(std::string_view s) {
            auto lc_ = std::unique_lock(lock_);
            value_ = s;

            if(not value_.empty()) active_ = true;
        };

        [[nodiscard]] std::string value() const {
            auto lc_ = std::shared_lock(lock_);
            return value_;
        }

        void active(bool newval) {
            active_ = newval;
        }
        [[nodiscard]] bool active() const {
            return active_;
        }
    };


    mutable std::weak_ptr<loglevel> my_loglevel {};

    // hold our own instance pointer
    std::weak_ptr<logan> logan_ {};
    std::shared_ptr<logan> logref() const { return logan_.lock(); }

public:
    static inline ContextFilter context_filter {};
    friend class logan;

    explicit logan_lite();
    explicit logan_lite(std::string topic) noexcept;
    logan_lite(logan_lite const& r);

    logan_lite& operator=(logan_lite const& r) {

        if(&r != this) {
            auto l_ = std::unique_lock(lock_);

            topic_ = r.topic_;
            context_ = r.context_;

            // even if my_loglevel can be non-null, we don't own it, so don't delete it here
            my_loglevel = r.my_loglevel;
        }

        return *this;
    }

    virtual std::string topic() const {
        auto l_ = std::shared_lock(lock_);
        return topic_;
    }
    virtual void topic(std::string const& s) {
        auto l_ = std::unique_lock(lock_);
        topic_ = s;
    }


    static std::string context() {
        return context_;
    }
    static void context(std::string_view s) {
        context_ = s;
    }


    virtual std::shared_ptr<loglevel> level() const;
    virtual void     level(loglevel const& l);

    template<class ... Args>
    void fat(const char* fmt, Args ... args) const {
        log(FAT, topic(), fmt, args ...);
    }
    template<class ... Args>
    void cri(const char* fmt, Args ... args) const {
        log(CRI, topic(), fmt, args ...);
    }
    template<class ... Args>
    void err(const char* fmt, Args ... args) const {
        log(ERR, topic(), fmt, args ...);
    }
    template<class ... Args>
    void war(const char* fmt, Args ... args) const {
        log(WAR, topic(), fmt, args ...);
    }
    template<class ... Args>
    void noti(const char* fmt, Args ... args) const {
        log(NOT, topic(), fmt, args ...);
    }
    template<class ... Args>
    void inf(const char* fmt, Args ... args) const {
        log(INF, topic(), fmt, args ...);
    }
    template<class ... Args>
    void dia(const char* fmt, Args ... args) const {
        log(DIA, topic(), fmt, args ...);
    }
    template<class ... Args>
    void deb(const char* fmt, Args ... args) const {
        log(DEB, topic(), fmt, args ...);
    }
    template<class ... Args>
    void dum(const char* fmt, Args ... args) const {
        log(DUM, topic(), fmt, args ...);
    }
    template<class ... Args>
    void ext(const char* fmt, Args ... args) const {
        log(EXT, topic(), fmt, args ...);
    }


    template<class ... Args>
    void log(loglevel const& lev, const std::string& topic, const char* fmt, Args ... args) const {
        if( *level() >= lev) {
            std::stringstream ms;

            if( not flag_test(lev.flags(),LOG_FLRAW) ) {

                if(logan_lite::context_filter.active()) {
                    if(logan_lite::context().empty()) return;
                    if(logan_lite::context().find( logan_lite::context_filter.value() ) == std::string::npos) {
                        return;
                    }
                }

                ms << "[ " << topic;
                if (!context().empty()) {
                    ms << " | " << context();
                }
                ms << "]: ";
            }
            ms << string_format(fmt, args...);

            auto lout = Log::get();

            if(lout) {
                lout->log(lev, ms.str());
            }
            else {
                std::cerr << "no LogOutput target\n";
            }
        }
    }

    template<class ... Args>
    uint64_t event(loglevel const& level, const char* fmt, Args ... args) const {
        auto lout = Log::get();

        if(lout) {
            return lout->events().insert(level, fmt, args...);
        }
        else {
            throw std::runtime_error("no logger to print events!");
        }

        return 0L;
    }

    template<class ... Args>
    uint64_t event_detail(uint64_t eid, const char* fmt, Args ... args) const {
        auto lout = Log::get();

        if(lout) {
            return lout->events().detail(eid, fmt, args...);
        }
        else {
            throw std::runtime_error("no logger to print events!");
        }

        return 0L;
    }

    auto event_block() const {
        auto lout = Log::get();

        if(not lout) throw std::runtime_error("no logger to print events!");
        return lout->events().event_block();
    }
};

#define LOGAN_LITE(x) \
    static logan_lite& log_instance() { static auto l_ = logan_lite((x)); return l_; }; \
    logan_lite& log = { log_instance() };                                                    \

struct logan_context {
    logan_context(std::string_view s) : orig_pref(logan_lite::context()) {
        logan_lite::context(s);
    }
    logan_context(logan_context const&) = delete;
    logan_context& operator=(logan_context const&) = delete;

    ~logan_context() { logan_lite::context(orig_pref); }

    std::string orig_pref;
};

class logan_tracer : public logan_lite {
public:
    explicit logan_tracer() : logan_lite("tracer"), start_(std::chrono::high_resolution_clock::now()) {}

    typedef std::vector<std::pair<long, std::string>> usec_msg_tupples;
    usec_msg_tupples& records() { return records_; }


    long delta() const {
        auto now = std::chrono::high_resolution_clock::now();

        std::chrono::microseconds d = std::chrono::duration_cast<std::chrono::microseconds>(now - start_);
        return d.count();
    }

    template<class C, class ... Args>
    void trace(C* object, const char* fmt, Args ... args) {
        trace( object->to_string(iINF),fmt, args ...);
    }

    template<class ... Args>
    void trace(std::string const& str, const char* fmt, Args ... args) {

        std::stringstream s;

        if(! name().empty() ) {
            s << name() << ": ";
        }

        s << str;
        s << " => ";
        s << string_format(fmt, args... );

        auto p = std::make_pair(delta(), s.str());
        records().push_back(p);
    }


    const std::string &name() const {
        return name_;
    }
    void name(const std::string &name) {
        name_ = name;
    }

private:
    std::chrono::high_resolution_clock::time_point start_;
    usec_msg_tupples records_;
    std::string name_;
};

class logan {
public:

    std::map <std::string, std::shared_ptr<loglevel>, std::less<>> topic_db_;

    std::shared_ptr<loglevel> entry(std::string const& subject) {
        std::scoped_lock<std::recursive_mutex> l_(lock_);

        auto it = topic_db_.find(subject);

        if(it != topic_db_.end()) {
            // found loglevel
            return std::atomic_load(&it->second);
        } else {

            auto l = std::make_shared<loglevel>(0,0);
            l->subject(subject);

            topic_db_.try_emplace(subject, std::move(l));
            return entry(subject);
        }
    }

    std::shared_ptr<loglevel> operator[] (std::string const& subject) {
        return entry(subject);
    }

    unsigned int level(std::string const& subject) {
        return entry(subject)->level();
    }


    // use selected object's loglevel. Returns its name;
    template<class T>
    static std::string use(const T& r) {
        get()[r.name()] = r.get_this_log_level();

        return r.name();
    }

    // return specifically crafted logger for the object (must be created with DECLARE_ and DEFINE_LOGGING!)
    // take current hr() and use it as the topic. Due its nature it's safer to use.
    // if you can assure object's lifetime during the logger life, use attach instead.
    template<class T>
    static logan_lite touch(T& ref) {
        logan_lite l = logan_lite();
        l.topic_ = ref.name();
        l.context_ = ref.hr();

        return l;
    }

    static logan_lite create(std::string const& s) {
        logan_lite l = logan_lite(s);

        return l;
    }

    template<class ... Args>
    static void fat(const std::string& topic, const char* fmt, Args ... args) {
        return log(FAT, topic, fmt, args ...);
    }

    template<class ... Args>
    static void cri(const std::string& topic, const char* fmt, Args ... args) {
        return log(CRI, topic, fmt, args ...);
    }

    template<class ... Args>
    static void err(const std::string& topic, const char* fmt, Args ... args) {
        return log(ERR, topic, fmt, args ...);
    }

    template<class ... Args>
    static void war(const std::string& topic, const char* fmt, Args ... args) {
        return log(WAR, topic, fmt, args ...);
    }

    template<class ... Args>
    static void noti(const std::string& topic, const char* fmt, Args ... args) {
        return log(NOT, topic, fmt, args ...);
    }

    template<class ... Args>
    static void inf(const std::string& topic, const char* fmt, Args ... args) {
        return log(INF, topic, fmt, args ...);
    }

    template<class ... Args>
    static void dia(const std::string& topic, const char* fmt, Args ... args) {
        return log(DIA, topic, fmt, args ...);
    }

    template<class ... Args>
    static void deb(const std::string& topic, const char* fmt, Args ... args) {
        return log(DEB, topic, fmt, args ...);
    }

    template<class ... Args>
    static void dum(const std::string& topic, const char* fmt, Args ... args) {
        return log(DUM, topic, fmt, args ...);
    }

    template<class ... Args>
    static void ext(const std::string& topic, const char* fmt, Args ... args) {
        return log(EXT, topic, fmt, args ...);
    }

    template<class ... Args>
    static void log(loglevel const& lev, const std::string& topic, const char* fmt, Args ... args) {

        auto& log = *get();
        auto topic_lev = log[topic];

        if( *topic_lev >= lev) {
            std::stringstream ms;
            ms << "[" << topic << "]: " << string_format(fmt, args...);

            Log::get()->log(lev, ms.str());
        }
    }

    [[nodiscard]] static std::shared_ptr<logan> get() {
        static auto l = std::make_shared<logan>();
        return std::atomic_load(&l);
    }

private:
    std::recursive_mutex lock_;
};


#endif //LOGAN_HPP
