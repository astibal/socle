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

#include <string>
#include <iostream>
#include <ctime>

#include <thread>
#include <mutex>
#include <vector>
#include <list>
#include <map>

#define NON 0
#define FAT 1
#define CRI 2
#define ERR 3
#define WAR 4
#define NOT 5
#define INF 6
#define DIA 7
#define DEB 8
#define DUM 9
#define EXT 10

#define DEB_DO_(x) if(lout.level() >= DEB) { (x); }
#define LEV_(x) (lout.level() >= (x) ? true : false ) 
#define LEV lout.level()

#define O_LOG_(lev,x,...) \
    if(lout.level() >= (lev)) { \
        lout.log(lev,(x),__VA_ARGS__); \
    }

#define O_LOGS_(lev,x) \
    if(lout.level() >= (lev)) { \
        lout.log(lev,(x)); \
    }

#define _FILE_ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)


/* Define macros that log without any extra checks in the object */

#define LOG_(lev,x,...) \
    if(lout.level() >= (lev)) { \
        if( ( lout.print_srcline() && lout.level() > INF ) || lout.print_srcline_always()) { \
            lout.log2(lev,_FILE_,__LINE__,(x),__VA_ARGS__); \
        } else { \
            lout.log(lev,(x),__VA_ARGS__); \
        } \
    }

#define LOGS_(lev,x) \
    if(lout.level() >= (lev)) { \
        if( ( lout.print_srcline() && lout.level() > INF ) || lout.print_srcline_always()) { \
            lout.log2(lev,_FILE_,__LINE__,(x)); \
        } else { \
            lout.log(lev,(x)); \
        } \
    }
	
#define T_LOG_(name,interval,lev,x,...) \
    if(lout.level() >= (lev)) { \
        if(lout.click_timer(name,interval)) { \
            LOG_(lev,x,__VA_ARGS__); \
        } \
    }

#define T_LOGS_(name,interval,lev,x) \
    if(lout.level() >= (lev)) { \
        if(lout.click_timer(name,interval)) { \
            LOGS_(lev,x); \
        } \
    }


/* Define macros that log in some cases also source file and line number enabling object log_level atribute check */

#define L_LOG_(lev,x,...) \
    if(log_level >= lev || lout.level() >= lev) { \
        lout.force(log_level >= lev); \
        if( ( lout.print_srcline() && lout.level() > INF ) || ( lout.print_srcline() && log_level > INF ) || lout.print_srcline_always()) { \
            lout.log2(lev,_FILE_,__LINE__,(x),__VA_ARGS__); \
        } else { \
            lout.log(lev,(x),__VA_ARGS__); \
        } \
    }

#define L_LOGS_(lev,x) \
    if(log_level >= lev || lout.level() >= lev) { \
        lout.force(log_level >= lev); \
        if( ( lout.print_srcline() && lout.level() > INF ) || ( lout.print_srcline() && log_level > INF ) || lout.print_srcline_always()) { \
            lout.log2(lev,_FILE_,__LINE__,(x)); \
        } else { \
            lout.log(lev,(x)); \
        } \
    }    
    

#define _T_L_LOG_(name,interval,lev,x,...) \
    if(this->log_level >= lev || lout.level() >= lev) { \
        lout.force(log_level >= lev); \
        if( ( lout.print_srcline() && lout.level() > INF ) || ( lout.print_srcline() && log_level > INF ) || lout.print_srcline_always()) { \
            if(lout.click_timer(name,interval)) { \
                LOG_(lev,x,__VA_ARGS__); \
            } \
        }\
    }

#define T_L_LOGS_(name,interval,lev,x) \
    if(this->log_level >= lev || lout.level() >= lev) { \
        lout.force(log_level >= lev); \
        if( ( lout.print_srcline() && lout.level() > INF ) || ( lout.print_srcline() && log_level > INF ) || lout.print_srcline_always()) { \
            if(lout.click_timer(name,interval)) { \
                LOGS_(lev,x); \
            } \
        } \
    }

    
/* Define macros that log objects with hr() function */    
    
#define LN_LOG_(lev,x,...) \
    if(log_level >= lev || lout.level() >= lev) { \
        lout.force(log_level >= lev); \
        if( ( lout.print_srcline() && lout.level() > INF ) || ( lout.print_srcline() && log_level > INF ) || lout.print_srcline_always()) { \
            lout.log2_w_name(lev,_FILE_,__LINE__,(hr()),(x),__VA_ARGS__); \
        } else { \
            lout.log_w_name(lev,(hr()),(x),__VA_ARGS__); \
        } \
    }

#define LN_LOGS_(lev,x) \
    if(log_level >= lev || lout.level() >= lev) { \
        lout.force(log_level >= lev); \
        if( ( lout.print_srcline() && lout.level() > INF ) || ( lout.print_srcline() && log_level > INF ) || lout.print_srcline_always()) { \
            lout.log2_w_name(lev,_FILE_,__LINE__,(hr()),(x)); \
        } else { \
            lout.log_w_name(lev,(hr()),(x)); \
        } \
    }    
    
        
#define T_LN_LOG_(name,interval,lev,x,...) \
    if(this->log_level >= lev || lout.level() >= lev) { \
        lout.force(log_level >= lev); \
        if( ( lout.print_srcline() && lout.level() > INF ) || ( lout.print_srcline() && log_level > INF ) || lout.print_srcline_always()) { \
            if(lout.click_timer(name,interval)) { \
                LN_LOG_(lev,x,__VA_ARGS__); \
            } \
        }\
    }

#define T_LN_LOGS_(name,interval,lev,x) \
    if(this->log_level >= lev || lout.level() >= lev) { \
        lout.force(log_level >= lev); \
        if( ( lout.print_srcline() && lout.level() > INF ) || ( lout.print_srcline() && log_level > INF ) || lout.print_srcline_always()) { \
            if(lout.click_timer(name,interval)) { \
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


#define PERIOD_START(interval) lout.periodic_start(interval);
#define PERIOD_END lout.periodic_end();


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
    const char* hr() { hr_ = get_name_func(); return hr_.c_str(); }; \
    static unsigned int& log_level_ref() { return log_level; } \
    static unsigned int log_level;                             \
private:                                                       \
    std::string hr_;

// takes argument of class name. It defines static variables
#define DEFINE_LOGGING(cls)   \
unsigned int cls::log_level = NON; \


#define DECLARE_C_NAME(string_name)     \
protected:                                \
    std::string name_ = string_name;   \
    std::string class_name_ = string_name;          \
public:                                             \
    virtual std::string& name()  { return name_; }          \
    virtual const char* c_name() { return name_.c_str(); }; \
    virtual void name(const char* n) { name_ = n; };        \
    virtual void name(std::string n) { name_ = n; };        \
    \
                    \
    virtual std::string class_name() { return class_name_; } \
    virtual const char* c_class_name() { return class_name_.c_str(); } \
    virtual int size_of() { return sizeof (*this); }

    
#include <algorithm>

std::string ESC_(std::string s);

#define ESC(x) ESC_(x).c_str()

struct timer {
    time_t last;
    unsigned int timeout;
};

typedef struct timer timer_tt;


class logger_profile {

public:  
    virtual ~logger_profile();    
    unsigned int level_ = 6;
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
    logger() { level_=0; period_ =5; target_names_[0]="unknown";};
    virtual ~logger() {};

    inline void level(unsigned int l) { level_ = l; };
    inline unsigned int level(void) const { return level_; };
    
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

    void log(unsigned int l, const std::string& fmt, ...);
    void log_w_name(unsigned int l, const char* n, const std::string& fmt, ...);
    void log_w_name(unsigned int l, std::string n, const std::string& fmt, ...);
    
    void log2(unsigned int l, const char* f, int li, const std::string& fmt, ...);
    void log2_w_name(unsigned int l, const char* f, int li, const char* n, const std::string& fmt, ...);
    void log2_w_name(unsigned int l, const char* f, int li, std::string n, const std::string& fmt, ...);
    
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
};

extern logger lout;

#endif // LOGGER_HPP
