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

#ifdef BUILD_RELEASE
#define  _ext  if(false) log.ext
#define  _dum  if(false) log.dum
#define  _deb  if(false) log.deb
#define  _if_deb  if(false)
#else
#define  _ext  if(*log.level() >= EXT) log.ext
#define  _dum  if(*log.level() >= DUM) log.dum
#define  _deb  if(*log.level() >= DEB) log.deb
#define  _if_deb  if(*log.level() >= DEB)
#endif
#define  _dia  if(*log.level() >= DIA) log.dia
#define  _inf  if(*log.level() >= INF) log.inf
#define  _not  if(*log.level() >= NOT) log.noti
#define  _war  if(*log.level() >= WAR) log.war
#define  _err  if(*log.level() >= ERR) log.err
#define  _cri  if(*log.level() >= CRI) log.cri
#define  _fat  if(*log.level() >= FAT) log.fat

#define  _cons  Log::get()->log_simple

class baseLoganMate {
public:
    [[nodiscard]] virtual  std::string& class_name() const = 0;
    [[nodiscard]] virtual std::string hr() const = 0;
};

class LoganMate : virtual public baseLoganMate {
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

protected:
    mutable std::shared_mutex lock_;
    // loging name in catalogue
    std::string topic_;

    // loging message prefix in log line
    std::string prefix_;

    mutable std::atomic<loglevel*> my_loglevel {0};

public:

    friend class logan;

    logan_lite() = default;
    explicit logan_lite(std::string str) noexcept: topic_(std::move(str)) {};
    logan_lite(logan_lite const& r): topic_(r.topic_), prefix_(r.prefix_), my_loglevel(r.my_loglevel.load()) {}
    logan_lite& operator=(logan_lite const& r) {

        if(&r != this) {
            auto l_ = std::unique_lock(lock_);

            topic_ = r.topic_;
            prefix_ = r.prefix_;

            // even if my_loglevel can be non-null, we don't own it, so don't delete it here
            my_loglevel = r.my_loglevel.load();
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


    virtual std::string prefix() const {
        auto l_ = std::shared_lock(lock_);
        return prefix_;
    }
    virtual void prefix(std::string const& s) {
        auto l_ = std::unique_lock(lock_);
        prefix_ = s;
    }


    virtual loglevel* level() const;
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
            if( ! flag_test(lev.flags(),LOG_FLRAW)) {
                ms << "[" << topic;
                if (!prefix().empty()) {
                    ms << "|" << prefix();
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
};

template <class T>
class logan_attached : public logan_lite {
public:
    logan_attached() = default;
    explicit logan_attached(T* ptr) : logan_lite(), ptr_(ptr) {}
    logan_attached(T* ptr, std::string  area) : logan_lite(), ptr_(ptr), area_(std::move(area)) {
        if(ptr_) topic(ptr->c_type());
    }

    inline logan_attached override() {
        return logan_attached(this->ptr_);
    }

    inline logan_attached override(std::string area) {
        return logan_attached(this->ptr_, area);
    }

    mutable loglevel* my_area_loglevel = nullptr;

    std::string topic() const override {

        // somebody's overridden topic, use it.
        if(! topic_.empty())
            return topic_;

        if(ptr_)
            return ptr_->c_type();

        return "(nullptr)";
    }
    void topic(std::string const& s) override {
        logan_lite::topic(s);
    }

    std::string prefix() const override {

        // somebody's overridden prefix, use it.
        if(! prefix_.empty())
            return prefix_;

        if(ptr_)
            return ptr_->hr();

        return "(nullptr)";
    }

    loglevel* level() const override;
    void level(loglevel const& l) override;
    virtual void this_level(loglevel const& l);

    void area(const std::string& ref);
    [[nodiscard]] std::string area() const {
        return area_;
    }

    using sub_area_t = mp::set<std::string>;
    const sub_area_t& sub_areas() const { return sub_areas_; };
    inline void sub_area(std::string const& str) { sub_areas_.insert(str); };
private:
    T* ptr_ = nullptr;

    std::string area_;
    sub_area_t sub_areas_;
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

    std::map <std::string, loglevel> topic_db_;

    loglevel* operator[] (std::string const& subject) {

        std::scoped_lock<std::recursive_mutex> l_(lock_);

        auto it = topic_db_.find(subject);

        if(it != topic_db_.end()) {
            // found loglevel
            return &it->second;
        } else {
            //auto* l = new loglevel(0,0);
            auto l = loglevel(0,0);
            l.subject(subject);

            // topic_db_.emplace( std::pair<std::string, loglevel*>(subject, l));
            topic_db_.try_emplace(subject, std::move(l));
            return this->operator[](subject);
        }
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
        l.prefix_ = ref.hr();

        return l;
    }

    template<class T>
    static logan_attached<T> attach(T* ptr) {
        logan_attached<T> l = logan_attached<T>(ptr);
        return l;
    }

    template<class T>
    static logan_attached<T> attach(T* ptr, std::string area) {
        logan_attached<T> l = logan_attached<T>(ptr, area);
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

        auto topic_lev = get()[topic];

        if( *topic_lev >= lev) {
            std::stringstream ms;
            ms << "[" << topic << "]: " << string_format(fmt, args...);

            Log::get()->log(lev, ms.str());
        }
    }

    static logan& get() {
        static logan l;
        return l;
    }

private:
    std::recursive_mutex lock_;
};

template <class T>
loglevel* logan_attached<T>::level() const {

    loglevel* l_this = nullptr;
    loglevel* l_name = nullptr;
    loglevel* l_area = nullptr;

    if(ptr_) {
        l_this = &ptr_->this_log_level_ref();
    }

    if( ! area().empty() ) {
        std::unique_lock l(lock_);

        if(! my_area_loglevel) {
            my_area_loglevel = logan::get()[area()];

            // iterate subareas
            if(! sub_areas().empty() ) {
                for(auto const& suba: sub_areas()) {
                    auto sa_level = logan::get()[suba];

                    // sub_area with higher verbosity
                    auto& lhs = *sa_level;
                    auto& rhs = *my_area_loglevel;
                    if( lhs > rhs) {

                        // override area verbosity
                        my_area_loglevel = sa_level;
                    }
                }
            }
        }
        l_area = my_area_loglevel;
    }

    l_name = logan_lite::level();

    if(l_this) {
        if (l_area && *l_area > *l_this)
            return l_area;

        if (l_name && *l_name > *l_this)
            return l_name;

        if (*l_this > NON)
            return l_this;
    }

    // return damn default
    return logan_lite::level();
}

template <class T>
void logan_attached<T>::level(loglevel const& l) {
    auto l_ = std::unique_lock(lock_);
    if(ptr_)
        ptr_->log_level_ref() = l;
}

template <class T>
void logan_attached<T>::this_level(loglevel const& l) {
    auto l_ = std::unique_lock(lock_);
    if(ptr_)
        ptr_->get_this_log_level() = l;
}

template <class T>
void logan_attached<T>::area(const std::string& ref) {
    auto l_ = std::unique_lock(lock_);

    if(area() == ref) return;

    area_ = ref;

      if(! my_area_loglevel) {
        my_area_loglevel = logan::get()[area_];
    }
}

#endif //LOGAN_HPP
