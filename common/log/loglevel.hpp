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
    explicit loglevel(unsigned int l) : level_(l), topic_(0) {}
    loglevel(unsigned int l, unsigned int t) : level_(l), topic_(t) {}
    loglevel(loglevel& l, unsigned int t) : level_(l.level_), topic_(t) {}
    loglevel(loglevel& l, unsigned int t, unsigned int f) : level_(l.level_), topic_(t), flags_(f) {}
    loglevel(unsigned int l, unsigned int t, loglevelmore* a) : level_(l), topic_(t), adv_(a) {}
    loglevel(loglevel& l, unsigned int t, loglevelmore* a) : level_(l.level_), topic_(t), adv_(a) {}
    loglevel(loglevel& l, unsigned int t, loglevelmore* a, unsigned int f) : level_(l.level_), topic_(t), adv_(a), flags_(f) {}


    [[nodiscard]] inline unsigned int level() const { return level_; }
    [[nodiscard]] inline unsigned int& level_ref() { return level_; }

    [[nodiscard]] inline unsigned int topic() const { return topic_; }
    [[nodiscard]] inline loglevelmore* more() const { return adv_; }
    [[nodiscard]] inline unsigned int flags() const { return flags_; }
    [[nodiscard]] inline std::string subject() const { return subject_; }
    [[nodiscard]] inline std::string area() const { return area_; }


    void level(unsigned int l) { level_ = l; }
    void topic(unsigned int t) { topic_ = t; }
    void more(loglevelmore* a) { adv_ = a; }
    void flags(unsigned int f) { flags_ = f; }
    void subject(std::string const& str) { subject_ = str; }
    void area(std::string const& str) { area_ = str; }

    [[nodiscard]] inline std::string str() const { return to_string(iINF); }
    [[nodiscard]] std::string to_string(int verbosity) const { return string_format("level:%d topic:%d",level_,topic_); };

private:
    unsigned int level_ {iINF};
    unsigned int topic_ {iNON};
    loglevelmore* adv_{nullptr};

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


    extern loglevel NON;
    extern loglevel FAT;
    extern loglevel CRI;
    extern loglevel ERR;
    extern loglevel WAR;
    extern loglevel NOT;
    extern loglevel INF;
    extern loglevel DIA;
    extern loglevel DEB;
    extern loglevel DUM;
    extern loglevel EXT;

    extern loglevelmore LOG_EXTOPIC;
    extern loglevelmore LOG_EXEXACT;
}

#endif