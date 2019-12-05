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
#else
#define  _ext  if(*log.level() >= EXT) log.ext
#define  _dum  if(*log.level() >= DUM) log.dum
#endif
#define  _deb  if(*log.level() >= DEB) log.deb
#define  _dia  if(*log.level() >= DIA) log.dia
#define  _inf  if(*log.level() >= INF) log.inf
#define  _not  if(*log.level() >= NOT) log.noti
#define  _war  if(*log.level() >= WAR) log.war
#define  _err  if(*log.level() >= ERR) log.err
#define  _cri  if(*log.level() >= CRI) log.cri
#define  _fat  if(*log.level() >= FAT) log.fat


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
    mutable std::mutex lock_;
    mutable loglevel* my_loglevel = nullptr;

    // loging name in catalogue
    std::string topic_;

    // loging message prefix in log line
    std::string prefix_;

public:

    friend class logan;

    logan_lite() = default;
    logan_lite(const std::string& str) : topic_(str) {};
    logan_lite(logan_lite const& r) {
        topic_  = r.topic_;
        prefix_ = r.prefix_;
        my_loglevel = r.my_loglevel;
    };
    void operator=(logan_lite const& r) {
        topic_  = r.topic_;
        prefix_ = r.prefix_;
        my_loglevel = r.my_loglevel;
    }

    virtual std::string topic() const { return topic_; }
    virtual        void topic(std::string s) { topic_ = s; }

    virtual std::string prefix() const { return prefix_; }
    virtual        void prefix(std::string s) { prefix_ = s; }

    virtual loglevel* level() const;
    virtual void     level(loglevel l);

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
    void log(loglevel lev, const std::string& topic, const char* fmt, Args ... args) const {
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

            get_logger()->log(lev, ms.str());
        }
    }
};

template <class T>
class logan_attached : public logan_lite {
public:
    logan_attached() = default;
    explicit logan_attached(T* ptr) : logan_lite(), ptr_(ptr) {}
    logan_attached(T* ptr, std::string  area) : logan_lite(), ptr_(ptr), area_(std::move(area)) {
        if(ptr_) topic(ptr->class_name());
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
            return ptr_->class_name();

        return "(nullptr)";
    }
    void topic(std::string s) override {
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
    void level(loglevel l) override;
    virtual void this_level(loglevel l);

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
    explicit logan_tracer() : logan_lite(), start_(std::chrono::high_resolution_clock::now()) {}

    typedef std::vector<std::pair<long, std::string>> usec_msg_tupples;
    usec_msg_tupples& records() { return records_; }


    long delta() const {
        auto now = std::chrono::high_resolution_clock::now();
        auto delta = now - start_;

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
    };


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

    std::map <std::string, loglevel*> topic_db_;

    loglevel* operator[] (std::string const& subject) {

        std::scoped_lock<std::recursive_mutex> l_(lock_);

        auto it = topic_db_.find(subject);

        if(it != topic_db_.end()) {
            // found loglevel
            return it->second;
        } else {
            loglevel* l = new loglevel(0,0);
            l->subject(subject);

            topic_db_.emplace( std::pair<std::string, loglevel*>(subject, l));
            return this->operator[](subject);
        }
    }


    // use selected object's loglevel. Returns its name;
    template<class T>
    static std::string use(const T& r) {
        get()[r.name()] = r.get_this_log_level();

        return r.name();
    };

    // return specifically crafted logger for the object (must be created with DECLARE_ and DEFINE_LOGGING!)
    // take current hr() and use it as the topic. Due its nature it's safer to use.
    // if you can assure object's lifetime during the logger life, use attach instead.
    template<class T>
    static logan_lite touch(T& ref) {
        logan_lite l = logan_lite();
        l.topic_ = ref.name();
        l.prefix_ = ref.hr();

        return l;
    };

    template<class T>
    static logan_attached<T> attach(T* ptr) {
        logan_attached<T> l = logan_attached<T>(ptr);
        return l;
    };

    template<class T>
    static logan_attached<T> attach(T* ptr, std::string area) {
        logan_attached<T> l = logan_attached<T>(ptr, area);
        return l;
    };


    static logan_lite create(std::string s) {
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
    static void log(loglevel lev, const std::string& topic, const char* fmt, Args ... args) {

        auto* topic_lev = get()[topic];

        if( *topic_lev >= lev) {
            std::stringstream ms;
            ms << "[" << topic << "]: " << string_format(fmt, args...);

            get_logger()->log(lev, ms.str());
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
        std::scoped_lock<std::mutex> l(lock_);

        if(! my_area_loglevel) {
            my_area_loglevel = logan::get()[area()];

            // iterate subareas
            if(! sub_areas().empty() ) {
                for(auto const& suba: sub_areas()) {
                    auto sa_level = logan::get()[suba];

                    // sub_area with higher verbosity
                    if( sa_level > my_area_loglevel) {

                        // override area verbosity
                        my_area_loglevel = sa_level;
                    }
                }
            }
        }
        l_area = my_area_loglevel;
    }

    l_name = logan_lite::level();

    if( l_area && *l_area > *l_this)
        return l_area;

    if( l_name && *l_name > *l_this )
        return l_name;

    if( l_this && *l_this > NON)
        return l_this;

    // return damn default
    return logan_lite::level();
}

template <class T>
void logan_attached<T>::level(loglevel l) {
    if(ptr_)
        ptr_->log_level_ref() = l;
}

template <class T>
void logan_attached<T>::this_level(loglevel l) {
    if(ptr_)
        ptr_->get_this_log_level() = l;
}

template <class T>
void logan_attached<T>::area(const std::string& ref) {

    if(area() == ref) return;

    area_ = ref;

    if(logan::get().topic_db_.find(area_) == logan::get().topic_db_.end()) {

        // set area logging level
        my_area_loglevel = logan::get()[area_];
    }
}

#endif //LOGAN_HPP
