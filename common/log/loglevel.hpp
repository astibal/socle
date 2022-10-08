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

#ifndef LOGLEVEL_HPP
#define LOGLEVEL_HPP

#include <string>
#include <mutex>

#include <display.hpp>
#include <log/loggermac.hpp>

struct logger_adv_info {
    logger_adv_info() = default;
    logger_adv_info(bool et, bool ee) : exclusive_topic(et), exclusive_exact(ee) {};
    bool exclusive_topic = false;  // don't log to generic log on true
    bool exclusive_exact = false;  // don't write to all topic logger, write to topic logger with the same code specified.
};
typedef logger_adv_info loglevelmore;

class loglevel {

public:
    explicit loglevel(unsigned int l) noexcept: level_(l), topic_(0) {}
    loglevel(unsigned int l, unsigned int t) noexcept: level_(l), topic_(t) {}
    loglevel(loglevel const& l, unsigned int t)  noexcept: level_(l.level_), topic_(t) {}
    loglevel(loglevel const& l, unsigned int t, unsigned int f)  noexcept: level_(l.level_), topic_(t), flags_(f) {}
    loglevel(unsigned int l, unsigned int t, loglevelmore const* a)  noexcept: level_(l), topic_(t), adv_(a) {}
    loglevel(loglevel const& l, unsigned int t, loglevelmore const* a)  noexcept: level_(l.level_), topic_(t), adv_(a) {}
    loglevel(loglevel const& l, unsigned int t, loglevelmore const* a, unsigned int f)  noexcept: level_(l.level_), topic_(t), adv_(a), flags_(f) {}


    [[nodiscard]] inline unsigned int level() const { return level_; }
    [[nodiscard]] inline unsigned int& level_ref() { return level_; }

    [[nodiscard]] inline unsigned int topic() const { return topic_; }
    [[nodiscard]] inline loglevelmore const* more() const { return adv_; }
    [[nodiscard]] inline unsigned int flags() const { return flags_; }
    [[nodiscard]] inline std::string subject() const { return subject_; }
    [[nodiscard]] inline std::string area() const { return area_; }


    void level(unsigned int l) { level_ = l; }
    void topic(unsigned int t) { topic_ = t; }
    void more(loglevelmore const* a) { adv_ = a; }
    void flags(unsigned int f) { flags_ = f; }
    void subject(std::string const& str) { subject_ = str; }
    void area(std::string const& str) { area_ = str; }

    [[nodiscard]] inline std::string str() const { return to_string(iINF); }
    [[nodiscard]] std::string to_string(int verbosity) const { return string_format("level:%d topic:%d",level_,topic_); };

private:
    unsigned int level_ {iINF};
    unsigned int topic_ {iNON};
    loglevelmore const* adv_{nullptr};

    unsigned int flags_{LOG_FLNONE};

    std::string subject_;
    std::string area_;
};


bool operator== (const loglevel& a, const loglevel& b);
bool operator== (const loglevel& a, const unsigned int& b);
bool operator== (const unsigned int& a, const loglevel& b);


bool operator<= (const loglevel& a, const loglevel& b);
bool operator<= (const loglevel& a, const unsigned int& b);
bool operator<= (const unsigned int& a, const loglevel& b);


bool operator>= (const loglevel& a, const loglevel& b);
bool operator>= (const loglevel& a, const unsigned int& b);
bool operator>= (const unsigned int& a, const loglevel& b);


bool operator!= (const loglevel& a, const loglevel& b);
bool operator!= (const loglevel& a, const unsigned int& b);
bool operator!= (const unsigned int& a, const loglevel& b);


bool operator> (const loglevel& a, const loglevel& b);
bool operator> (const loglevel& a, const unsigned int& b);
bool operator> (const unsigned int& a, const loglevel& b);


bool operator< (const loglevel& a, const loglevel& b);
bool operator< (const loglevel& a, const unsigned int& b);
bool operator< (const unsigned int& a, const loglevel& b);

loglevel operator-(const loglevel& a, const loglevel& b);
loglevel operator-(const loglevel& a, const unsigned int& b);
loglevel operator+(const loglevel& a, const unsigned int& b);


namespace socle::log::level {


    extern const loglevel NON;
    extern const loglevel FAT;
    extern const loglevel CRI;
    extern const loglevel ERR;
    extern const loglevel WAR;
    extern const loglevel NOT;
    extern const loglevel INF;
    extern const loglevel DIA;
    extern const loglevel DEB;
    extern const loglevel DUM;
    extern const loglevel EXT;

    extern const loglevelmore LOG_EXTOPIC;
    extern const loglevelmore LOG_EXEXACT;
}

struct logdata_t {
    logdata_t() = default;
    logdata_t(logdata_t const&) {};
    logdata_t& operator=(logdata_t const&) { return *this; };
    std::mutex mtx_;


    bool empty() const { return not hr_.has_value(); }  \
    std::optional<std::string> optional() const { return hr_; }  \

    mutable std::optional<std::string> hr_;
    static inline loglevel lg_ {socle::log::level::NON};
};

#endif