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

#include <string>
#include <iostream>
#include <ctime>

#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include <map>

#include <display.hpp>
// logging levels

#define iNON 0
#define iFAT 1
#define iCRI 2
#define iERR 3
#define iWAR 4
#define iNOT 5
#define iINF 6
#define iDIA 7
#define iDEB 8
#define iDUM 9
#define iEXT 10

struct logger_adv_info {
    logger_adv_info() {}
    logger_adv_info(bool et, bool ee) : exclusive_topic(et), exclusive_exact(ee) {};
    bool exclusive_topic = false;  // don't log to generic log on true
    bool exclusive_exact = false;  // don't write to all topic logger, write to topic logger with the same code specified.
};
typedef logger_adv_info loglevelmore;

extern loglevelmore LOG_EXTOPIC;
extern loglevelmore LOG_EXEXACT;

#define LOG_FLNONE 0x00000000
#define LOG_FLRAW  0x00000001  // don't print out any dates, or additional data  on the line, just this message

struct logger_level {
    logger_level(unsigned int l, unsigned int t) : level_(l),topic_(t) {}
    logger_level(logger_level& l, unsigned int t) : level_(l.level_), topic_(t) {}
    logger_level(logger_level& l, unsigned int t, unsigned int f) : level_(l.level_), topic_(t), flags_(f) {}
    logger_level(unsigned int l, unsigned int t,loglevelmore* a) : level_(l),topic_(t), adv_(a) {}
    logger_level(logger_level& l, unsigned int t, loglevelmore* a) : level_(l.level_), topic_(t), adv_(a) {}
    logger_level(logger_level& l, unsigned int t, loglevelmore* a, unsigned int f) : level_(l.level_), topic_(t), adv_(a), flags_(f) {}

    
    inline unsigned int level() const { return level_; }
    inline unsigned int topic() const { return topic_; }
    const loglevelmore* more(void) const { return adv_; }

    void level(unsigned int l) { level_ = l; }
    void topic(unsigned int t) { topic_ = t; }
    void more(loglevelmore* a) { adv_ = a; }
    
    unsigned int level_ {iINF};
    unsigned int topic_ {iNON};
    loglevelmore* adv_{nullptr};
    
    unsigned int flags_{LOG_FLNONE};
    
    std::string to_string(int verbosity=iINF) { return string_format("level:%d topic:%d",level_,topic_); };
};

typedef struct logger_level loglevel;

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



// logging topics

#define GEN  0x00000000
#define CRT  0x00010000  // SSL/PKI topic
#define ATH  0x00020000  // user validation (AAA)

#define KEYS 0x00008000  // dump all secrets


#define DEB_DO_(x) if(get_logger()->level() >= DEB) { (x); }
#define LEV_(x) (get_logger()->level() >= (x) ? true : false ) 
#define LEV get_logger()->level()

#define O_LOG_(lev,x,...) \
    if(get_logger()->level() >= (lev)) { \
        get_logger()->log(lev,(x),__VA_ARGS__); \
    }

#define O_LOGS_(lev,x) \
    if(get_logger()->level() >= (lev)) { \
        get_logger()->log(lev,(x)); \
    }

#define _FILE_ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)


/* Define macros that log without any extra checks in the object */

#define LOG_(lev,x,...) \
    if(get_logger()->level() >= (lev)) { \
        if( ( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || get_logger()->print_srcline_always() ) && !flag_test((lev).flags_,LOG_FLRAW)) { \
            get_logger()->log2(lev,_FILE_,__LINE__,(x),__VA_ARGS__); \
        } else { \
            get_logger()->log(lev,(x),__VA_ARGS__); \
        } \
    }

#define LOGS_(lev,x) \
    if(get_logger()->level() >= (lev)) { \
        if( ( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || get_logger()->print_srcline_always() ) && !flag_test((lev).flags_,LOG_FLRAW)) { \
            get_logger()->log2(lev,_FILE_,__LINE__,(x)); \
        } else { \
            get_logger()->log(lev,(x)); \
        } \
    }
	
#define T_LOG_(name,interval,lev,x,...) \
    if(get_logger()->level() >= (lev)) { \
        if(get_logger()->click_timer(name,interval)) { \
            LOG_(lev,x,__VA_ARGS__); \
        } \
    }

#define T_LOGS_(name,interval,lev,x) \
    if(get_logger()->level() >= (lev)) { \
        if(get_logger()->click_timer(name,interval)) { \
            LOGS_(lev,x); \
        } \
    }


/* Define macros that log in some cases also source file and line number enabling object log_level atribute check */

#define L_LOG_(lev,x,...) \
    if(log_level >= lev || get_logger()->level() >= lev) { \
        get_logger()->force(log_level >= lev); \
        if( ( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || ( get_logger()->print_srcline() && log_level > INF ) || get_logger()->print_srcline_always() ) && !flag_test((lev).flags_,LOG_FLRAW)) { \
            get_logger()->log2(lev,_FILE_,__LINE__,(x),__VA_ARGS__); \
        } else { \
            get_logger()->log(lev,(x),__VA_ARGS__); \
        } \
    }

#define L_LOGS_(lev,x) \
    if(log_level >= lev || get_logger()->level() >= lev) { \
        get_logger()->force(log_level >= lev); \
        if( ( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || ( get_logger()->print_srcline() && log_level > INF ) || get_logger()->print_srcline_always() ) && !flag_test((lev).flags_,LOG_FLRAW)) { \
            get_logger()->log2(lev,_FILE_,__LINE__,(x)); \
        } else { \
            get_logger()->log(lev,(x)); \
        } \
    }    
    

#define _T_L_LOG_(name,interval,lev,x,...) \
    if(this->log_level >= lev || get_logger()->level() >= lev) { \
        get_logger()->force(log_level >= lev); \
        if( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || ( get_logger()->print_srcline() && log_level > INF ) || get_logger()->print_srcline_always()) { \
            if(get_logger()->click_timer(name,interval)) { \
                LOG_(lev,x,__VA_ARGS__); \
            } \
        }\
    }

#define T_L_LOGS_(name,interval,lev,x) \
    if(this->log_level >= lev || get_logger()->level() >= lev) { \
        get_logger()->force(log_level >= lev); \
        if( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || ( get_logger()->print_srcline() && log_level > INF ) || get_logger()->print_srcline_always()) { \
            if(get_logger()->click_timer(name,interval)) { \
                LOGS_(lev,x); \
            } \
        } \
    }

    
/* Define macros that log objects with hr() function */    
    
#define LN_LOG_(lev,x,...) \
    if(this->get_this_log_level() >= lev || get_logger()->level() >= lev) { \
        get_logger()->force(log_level >= lev); \
        if( ( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || ( get_logger()->print_srcline() && log_level > INF ) || get_logger()->print_srcline_always() ) && !flag_test((lev).flags_,LOG_FLRAW)) { \
            get_logger()->log2_w_name(lev,_FILE_,__LINE__,(hr()),(x),__VA_ARGS__); \
        } else { \
            get_logger()->log_w_name(lev,(hr()),(x),__VA_ARGS__); \
        } \
    }

#define LN_LOGS_(lev,x) \
    if(this->get_this_log_level() >= lev || get_logger()->level() >= lev) { \
        get_logger()->force(log_level >= lev); \
        if( ( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || ( get_logger()->print_srcline() && log_level > INF ) || get_logger()->print_srcline_always() ) && !flag_test((lev).flags_,LOG_FLRAW)) { \
            get_logger()->log2_w_name(lev,_FILE_,__LINE__,(hr()),(x)); \
        } else { \
            get_logger()->log_w_name(lev,(hr()),(x)); \
        } \
    }    
    
        
#define T_LN_LOG_(name,interval,lev,x,...) \
    if(this->get_this_log_level() >= lev || get_logger()->level() >= lev) { \
        get_logger()->force(log_level >= lev); \
        if( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || ( get_logger()->print_srcline() && log_level > INF ) || get_logger()->print_srcline_always()) { \
            if(get_logger()->click_timer(name,interval)) { \
                LN_LOG_(lev,x,__VA_ARGS__); \
            } \
        }\
    }

#define T_LN_LOGS_(name,interval,lev,x) \
    if(this->get_this_log_level() >= lev || get_logger()->level() >= lev) { \
        get_logger()->force(log_level >= lev); \
        if( ( get_logger()->print_srcline() && get_logger()->level() > INF ) || ( get_logger()->print_srcline() && log_level > INF ) || get_logger()->print_srcline_always())) { \
            if(get_logger()->click_timer(name,interval)) { \
                LN_LOGS_(lev,x); \
            } \
        } \
    }
    

/* short names for macros without object attribute check */
    
#define EXT_(x,...) LOG_(EXT,(x),__VA_ARGS__)
#define EXTS_(x,...) LOGS_(EXT,(x))
#define T_EXT_(n,i,x,...) T_LOG_(n,i,EXT,(x),__VA_ARGS__)
#define T_EXTS_(n,i,x) T_LOGS_(n,i,EXT,(x))

#define DUM_(x,...) LOG_(DUM,(x),__VA_ARGS__)
#define DUMS_(x,...) LOGS_(DUM,(x))
#define T_DUM_(n,i,x,...) T_LOG_(n,i,DUM,(x),__VA_ARGS__)
#define T_DUMS_(n,i,x) T_LOGS_(n,i,DUM,(x))
	
#define DEB_(x,...) LOG_(DEB,(x),__VA_ARGS__)
#define DEBS_(x,...) LOGS_(DEB,(x))
#define T_DEB_(n,i,x,...) T_LOG_(n,i,DEB,(x),__VA_ARGS__)
#define T_DEBS_(n,i,x) T_LOGS_(n,i,DEB,(x))


#define DIA_(x,...) LOG_(DIA,(x),__VA_ARGS__)
#define DIAS_(x,...) LOGS_(DIA,(x))
#define T_DIA_(n,i,x,...) T_LOG_(n,i,DIA,(x),__VA_ARGS__)
#define T_DIAS_(n,i,x) T_LOGS_(n,i,DIA,(x))


#define INF_(x,...) LOG_(INF,(x),__VA_ARGS__)
#define INFS_(x,...) LOGS_(INF,(x))
#define T_INF_(n,i,x,...) T_LOG_(n,i,INF,(x),__VA_ARGS__)
#define T_INFS_(n,i,x) T_LOGS_(n,i,INF,(x))


#define NOT_(x,...) LOG_(NOT,(x),__VA_ARGS__)
#define NOTS_(x,...) LOGS_(NOT,(x))
#define T_NOT_(n,i,x,...) T_LOG_(n,i,NOT,(x),__VA_ARGS__)
#define T_NOTS_(n,i,x) T_LOGS_(n,i,NOT,(x))


#define WAR_(x,...) LOG_(WAR,(x),__VA_ARGS__)
#define WARS_(x,...) LOGS_(WAR,(x))
#define T_WAR_(n,i,x,...) T_LOG_(n,i,WAR,(x),__VA_ARGS__)
#define T_WARS_(n,i,x) T_LOGS_(n,i,WAR,(x))


#define ERR_(x,...) LOG_(ERR,(x),__VA_ARGS__)
#define ERRS_(x,...) LOGS_(ERR,(x))
#define T_ERR_(n,i,x,...) T_LOG_(n,i,ERR,(x),__VA_ARGS__)
#define T_ERRS_(n,i,x) T_LOGS_(n,i,ERR,(x))


#define CRI_(x,...) LOG_(CRI,(x),__VA_ARGS__)
#define CRIS_(x,...) LOGS_(CRI,(x))
#define T_CRI_(n,i,x,...) T_LOG_(n,i,CRI,(x),__VA_ARGS__)
#define T_CRIS_(n,i,x) T_LOGS_(n,i,CRI,(x))


#define FAT_(x,...) LOG_(FAT,(x),__VA_ARGS__)
#define FATS_(x,...) LOGS_(FAT,(x))
#define T_FAT_(n,i,x,...) T_LOG_(n,i,FAT,(x),__VA_ARGS__)
#define T_FATS_(n,i,x) T_LOGS_(n,i,FAT,(x))


#define NON_(x,...) LOG_(NON,(x),__VA_ARGS__)
#define NONS_(x,...) LOGS_(NON,(x))
#define T_NON_(n,i,x,...) T_LOG_(n,i,NON,(x),__VA_ARGS__)
#define T_NONS_(n,i,x) T_LOGS_(n,i,NON,(x))


/* Macros with 'log_level' attribute support */

#define LOG__(lev,x,...) L_LOG_((lev),(x),__VA_ARGS__)
#define LOGS__(lev,x) L_LOGS_((lev),(x))

#define EXT__(x,...) L_LOG_(EXT,(x),__VA_ARGS__)
#define EXTS__(x,...) L_LOGS_(EXT,(x))
#define T_EXT__(n,i,x,...) T_L_LOG_(n,i,EXT,(x),__VA_ARGS__)
#define T_EXTS__(n,i,x) T_L_LOGS_(n,i,EXT,(x))

#define DUM__(x,...) L_LOG_(DUM,(x),__VA_ARGS__)
#define DUMS__(x,...) L_LOGS_(DUM,(x))
#define T_DUM__(n,i,x,...) T_L_LOG_(n,i,DUM,(x),__VA_ARGS__)
#define T_DUMS__(n,i,x) T_L_LOGS_(n,i,DUM,(x))
        
#define DEB__(x,...) L_LOG_(DEB,(x),__VA_ARGS__)
#define DEBS__(x,...) L_LOGS_(DEB,(x))
#define T_DEB__(n,i,x,...) T_L_LOG_(n,i,DEB,(x),__VA_ARGS__)
#define T_DEBS__(n,i,x) T_L_LOGS_(n,i,DEB,(x))


#define DIA__(x,...) L_LOG_(DIA,(x),__VA_ARGS__)
#define DIAS__(x,...) L_LOGS_(DIA,(x))
#define T_DIA__(n,i,x,...) T_L_LOG_(n,i,DIA,(x),__VA_ARGS__)
#define T_DIAS__(n,i,x) T_L_LOGS_(n,i,DIA,(x))


#define INF__(x,...) L_LOG_(INF,(x),__VA_ARGS__)
#define INFS__(x,...) L_LOGS_(INF,(x))
#define T_INF__(n,i,x,...) T_L_LOG_(n,i,INF,(x),__VA_ARGS__)
#define T_INFS__(n,i,x) T_L_LOGS_(n,i,INF,(x))


#define NOT__(x,...) L_LOG_(NOT,(x),__VA_ARGS__)
#define NOTS__(x,...) L_LOGS_(NOT,(x))
#define T_NOT__(n,i,x,...) T_L_LOG_(n,i,NOT,(x),__VA_ARGS__)
#define T_NOTS__(n,i,x) T_L_LOGS_(n,i,NOT,(x))


#define WAR__(x,...) L_LOG_(WAR,(x),__VA_ARGS__)
#define WARS__(x,...) L_LOGS_(WAR,(x))
#define T_WAR__(n,i,x,...) T_L_LOG_(n,i,WAR,(x),__VA_ARGS__)
#define T_WARS__(n,i,x) T_L_LOGS_(n,i,WAR,(x))


#define ERR__(x,...) L_LOG_(ERR,(x),__VA_ARGS__)
#define ERRS__(x,...) L_LOGS_(ERR,(x))
#define T_ERR__(n,i,x,...) T_L_LOG_(n,i,ERR,(x),__VA_ARGS__)
#define T_ERRS__(n,i,x) T_L_LOGS_(n,i,ERR,(x))


#define CRI__(x,...) L_LOG_(CRI,(x),__VA_ARGS__)
#define CRIS__(x,...) L_LOGS_(CRI,(x))
#define T_CRI__(n,i,x,...) T_L_LOG_(n,i,CRI,(x),__VA_ARGS__)
#define T_CRIS__(n,i,x) T_L_LOGS_(n,i,CRI,(x))


#define FAT__(x,...) L_LOG_(FAT,(x),__VA_ARGS__)
#define FATS__(x,...) L_LOGS_(FAT,(x))
#define T_FAT__(n,i,x,...) T_L_LOG_(n,i,FAT,(x),__VA_ARGS__)
#define T_FATS__(n,i,x) T_L_LOGS_(n,i,FAT,(x))


#define NON__(x,...) L_LOG_(NON,(x),__VA_ARGS__)
#define NONS__(x,...) L_LOGS_(NON,(x))
#define T_NON__(n,i,x,...) T_L_LOG_(n,i,NON,(x),__VA_ARGS__)
#define T_NONS__(n,i,x) T_L_LOGS_(n,i,NON,(x))


/* Macros with support of both 'log_level' and hr() call */

#define LOG___(lev,x,...) LN_LOG_((lev),(x),__VA_ARGS__)
#define LOGS___(lev,x) LN_LOGS_((lev),(x))

#define EXT___(x,...) LN_LOG_(EXT,(x),__VA_ARGS__)
#define EXTS___(x,...) LN_LOGS_(EXT,(x))
#define T_EXT___(n,i,x,...) T_LN_LOG_(n,i,EXT,(x),__VA_ARGS__)
#define T_EXTS___(n,i,x) T_LN_LOGS_(n,i,EXT,(x))

#define DUM___(x,...) LN_LOG_(DUM,(x),__VA_ARGS__)
#define DUMS___(x,...) LN_LOGS_(DUM,(x))
#define T_DUM___(n,i,x,...) T_LN_LOG_(n,i,DUM,(x),__VA_ARGS__)
#define T_DUMS___(n,i,x) T_LN_LOGS_(n,i,DUM,(x))
        
#define DEB___(x,...) LN_LOG_(DEB,(x),__VA_ARGS__)
#define DEBS___(x,...) LN_LOGS_(DEB,(x))
#define T_DEB___(n,i,x,...) T_LN_LOG_(n,i,DEB,(x),__VA_ARGS__)
#define T_DEBS___(n,i,x) T_LN_LOGS_(n,i,DEB,(x))


#define DIA___(x,...) LN_LOG_(DIA,(x),__VA_ARGS__)
#define DIAS___(x,...) LN_LOGS_(DIA,(x))
#define T_DIA___(n,i,x,...) T_LN_LOG_(n,i,DIA,(x),__VA_ARGS__)
#define T_DIAS___(n,i,x) T_LN_LOGS_(n,i,DIA,(x))


#define INF___(x,...) LN_LOG_(INF,(x),__VA_ARGS__)
#define INFS___(x,...) LN_LOGS_(INF,(x))
#define T_INF___(n,i,x,...) T_LN_LOG_(n,i,INF,(x),__VA_ARGS__)
#define T_INFS___(n,i,x) T_LN_LOGS_(n,i,INF,(x))


#define NOT___(x,...) LN_LOG_(NOT,(x),__VA_ARGS__)
#define NOTS___(x,...) LN_LOGS_(NOT,(x))
#define T_NOT___(n,i,x,...) T_LN_LOG_(n,i,NOT,(x),__VA_ARGS__)
#define T_NOTS___(n,i,x) T_LN_LOGS_(n,i,NOT,(x))


#define WAR___(x,...) LN_LOG_(WAR,(x),__VA_ARGS__)
#define WARS___(x,...) LN_LOGS_(WAR,(x))
#define T_WAR___(n,i,x,...) T_LN_LOG_(n,i,WAR,(x),__VA_ARGS__)
#define T_WARS___(n,i,x) T_LN_LOGS_(n,i,WAR,(x))


#define ERR___(x,...) LN_LOG_(ERR,(x),__VA_ARGS__)
#define ERRS___(x,...) LN_LOGS_(ERR,(x))
#define T_ERR___(n,i,x,...) T_LN_LOG_(n,i,ERR,(x),__VA_ARGS__)
#define T_ERRS___(n,i,x) T_LN_LOGS_(n,i,ERR,(x))


#define FAT___(x,...) LN_LOG_(FAT,(x),__VA_ARGS__)
#define FATS___(x,...) LN_LOGS_(FAT,(x))
#define T_FAT___(n,i,x,...) T_LN_LOG_(n,i,FAT,(x),__VA_ARGS__)
#define T_FATS___(n,i,x) T_LN_LOGS_(n,i,FAT,(x))


#define NON___(x,...) LN_LOG_(NON,(x),__VA_ARGS__)
#define NONS___(x,...) LN_LOGS_(NON,(x))
#define T_NON___(n,i,x,...) T_LN_LOG_(n,i,NON,(x),__VA_ARGS__)
#define T_NONS___(n,i,x) T_LN_LOGS_(n,i,NON,(x))


#define PERIOD_START(interval) get_logger()->periodic_start(interval);
#define PERIOD_END get_logger()->periodic_end();


#define VA_BUFFSIZE 2048
// process valist, and fill std::string
#define PROCESS_VALIST(str,fmt)     \
    int size = VA_BUFFSIZE;         \
    va_list ap;                     \
    while (1) {                     \
        str.resize(size);           \
        va_start(ap, fmt);          \
        int n = vsnprintf((char *)str.c_str(), size-1, fmt.c_str(), ap);  \
        va_end(ap);                 \
                                    \
        if (n > -1 && n < size) {   \
            str.resize(n);          \
                break;              \
        }                           \
                                    \
        if (n > -1)                 \
            size = n + 1;           \
        else                        \
            size *= 2;              \
    }                               \


// EXTENDED LOGGING HELPER MACROS

// takes argument of pointer to function which returns std::string, indicate object name. 
#define DECLARE_LOGGING(get_name_func)  \
public:                                      \
    const char* hr() { hr_ = this->get_name_func(); return hr_.c_str(); }; \
    static loglevel& log_level_ref() { return log_level; } \
    static loglevel log_level;                             \
    virtual loglevel get_this_log_level() const { return this_log_level_ > log_level ? this_log_level_: log_level ; }     \
    virtual void set_this_log_level(loglevel nl) { this_log_level_ = nl; }  \
private:                                                       \
    std::string hr_;                                           \
    loglevel this_log_level_ = NON;

// takes argument of class name. It defines static variables
#define DEFINE_LOGGING(cls)   \
loglevel cls::log_level = NON; \

#define DEFINE_TEMPLATE_LOGGING(cls)   \
template<> loglevel cls::log_level = NON; \


#define DECLARE_C_NAME(string_name)     \
private:                                \
    std::string name_ = string_name;   \
    std::string class_name_ = string_name;          \
public:                                             \
    virtual std::string& name()  { return this->name_; }          \
    virtual const char* c_name() { return this->name_.c_str(); }; \
    virtual void name(const char* n) { name_ = n; };        \
    virtual void name(std::string n) { name_ = n; };        \
    \
                    \
    virtual std::string class_name() { return this->class_name_; } \
    virtual const char* c_class_name() { return this->class_name_.c_str(); } \
    virtual int size_of() { return sizeof (*this); }

    
#define DECLARE_DEF_TO_STRING \
    virtual std::string to_string(int verbosity=iINF) { return this->class_name(); };    
    
#include <algorithm>

std::string ESC_(std::string s);

#define ESC(x) ESC_(x).c_str()

struct timer {
    time_t last;
    unsigned int timeout;
};

typedef struct timer timer_tt;

struct logger_profile_syslog {
    int facility = 23; // local7
    int severity = 6;  // information;
    
    inline int prival() const { return facility * 8 + ( (severity > DEB) ? DEB.level_ : severity ); };
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

    // next print output will be forced => printed regardless of it's level
    bool forced_ = false;
    
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

    bool click_timer(std::string, int);


    std::list<std::ostream*>& targets() { return targets_; }
    void targets(std::string name, std::ostream* o) { targets_.push_back(o); target_names_[(uint64_t)o] = name; }

    std::list<int>& remote_targets() { return remote_targets_; }
    void remote_targets(std::string name, int s) { remote_targets_.push_back(s); target_names_[s] = name; }

    int virtual write_log(loglevel level, std::string& sss);
    
    bool should_log_topic(loglevel& writer, loglevel& msg);
    
    void log(loglevel l, const std::string& fmt, ...);
    void log_w_name(loglevel l, const char* n, const std::string& fmt, ...);
    void log_w_name(loglevel l, std::string n, const std::string& fmt, ...);
    
    void log2(loglevel l, const char* f, int li, const std::string& fmt, ...);
    void log2_w_name(loglevel l, const char* f, int li, const char* n, const std::string& fmt, ...);
    void log2_w_name(loglevel l, const char* f, int li, std::string n, const std::string& fmt, ...);
    
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
    
    void force(bool b) { forced_ = b; }

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
    // @return log level difference, therefore negative if we decreased logging level, zero if unchanged, positive if log level is raised.
    loglevel adjust_level();
};

extern logger* lout_;

extern logger* get_logger();
extern logger* create_default_logger();
extern void set_logger(logger*);



#endif // LOGGER_HPP
