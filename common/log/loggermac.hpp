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

#ifndef LOGGERMAC_HPP
#define LOGGERMAC_HPP

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

// logging topics

#define GEN  0x00000000
#define CRT  0x00010000  // SSL/PKI topic
#define ATH  0x00020000  // user validation (AAA)

#define KEYS 0x00008000  // dump all secrets

#define LOG_FLNONE 0x00000000
#define LOG_FLRAW  0x00000001  // don't print out any dates, or additional data  on the line, just this message


#define DEB_DO_(x) if(LogOutput::get()->level() >= DEB) { (x); }
#define LEV_(x) (LogOutput::get()->level() >= (x) ? true : false )
#define LEV LogOutput::get()->level()

#define O_LOG_(lev,x,...) \
    if(LogOutput::get()->level() >= (lev)) { \
        LogOutput::get()->log(lev,(x),__VA_ARGS__); \
    }

#define O_LOGS_(lev,x) \
    if(LogOutput::get()->level() >= (lev)) { \
        LogOutput::get()->log(lev,(x)); \
    }

#define _FILE_ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)


/* Define macros that log without any extra checks in the object */

#define LOG_(lev,x,...) \
    if(LogOutput::get()->level() >= (lev)) { \
        if( ( ( LogOutput::get()->print_srcline() && LogOutput::get()->level() > INF ) || LogOutput::get()->print_srcline_always() ) \
              && !flag_test((lev).flags(),LOG_FLRAW)) { \
            LogOutput::get()->log2(lev,_FILE_,__LINE__,(x),__VA_ARGS__); \
        } else { \
            LogOutput::get()->log(lev,(x),__VA_ARGS__); \
        } \
    }

#define LOGS_(lev,x) \
    if(LogOutput::get()->level() >= (lev)) { \
        if( ( ( LogOutput::get()->print_srcline() && LogOutput::get()->level() > INF ) || LogOutput::get()->print_srcline_always() ) \
              && !flag_test((lev).flags(),LOG_FLRAW)) { \
            LogOutput::get()->log2(lev,_FILE_,__LINE__,(x)); \
        } else { \
            LogOutput::get()->log(lev,(x)); \
        } \
    }

#define T_LOG_(name,interval,lev,x,...) \
    if(LogOutput::get()->level() >= (lev)) { \
        if(LogOutput::get()->click_timer(name,interval)) { \
            LOG_(lev,x,__VA_ARGS__); \
        } \
    }

#define T_LOGS_(name,interval,lev,x) \
    if(LogOutput::get()->level() >= (lev)) { \
        if(LogOutput::get()->click_timer(name,interval)) { \
            LOGS_(lev,x); \
        } \
    }


/* Define macros that log in some cases also source file and line number enabling object log_level attribute check */

#define L_LOG_(lev,x,...) \
    if(log_level >= lev || LogOutput::get()->level() >= lev) { \
        if( ( ( LogOutput::get()->print_srcline() && LogOutput::get()->level() > INF ) || ( LogOutput::get()->print_srcline() && log_level > INF ) || LogOutput::get()->print_srcline_always() ) && !flag_test((lev).flags(),LOG_FLRAW)) { \
            LogOutput::get()->log2(lev,_FILE_,__LINE__,(x),__VA_ARGS__); \
        } else { \
            LogOutput::get()->log(lev,(x),__VA_ARGS__); \
        } \
    }

#define L_LOGS_(lev,x) \
    if(log_level >= lev || LogOutput::get()->level() >= lev) { \
        if( ( ( LogOutput::get()->print_srcline() && LogOutput::get()->level() > INF ) || ( LogOutput::get()->print_srcline() && log_level > INF ) || LogOutput::get()->print_srcline_always() ) && !flag_test((lev).flags(),LOG_FLRAW)) { \
            LogOutput::get()->log2(lev,_FILE_,__LINE__,(x)); \
        } else { \
            LogOutput::get()->log(lev,(x)); \
        } \
    }


#define _T_L_LOG_(name,interval,lev,x,...) \
    if(this->log_level >= lev || LogOutput::get()->level() >= lev) { \
        if( ( LogOutput::get()->print_srcline() && LogOutput::get()->level() > INF ) || ( LogOutput::get()->print_srcline() && log_level > INF ) || LogOutput::get()->print_srcline_always()) { \
            if(LogOutput::get()->click_timer(name,interval)) { \
                LOG_(lev,x,__VA_ARGS__); \
            } \
        }\
    }

#define T_L_LOGS_(name,interval,lev,x) \
    if(this->log_level >= lev || LogOutput::get()->level() >= lev) { \
        if( ( LogOutput::get()->print_srcline() && LogOutput::get()->level() > INF ) || ( LogOutput::get()->print_srcline() && log_level > INF ) || LogOutput::get()->print_srcline_always()) { \
            if(LogOutput::get()->click_timer(name,interval)) { \
                LOGS_(lev,x); \
            } \
        } \
    }


/* Define macros that log objects with hr() function */

#define LN_LOG_(lev,x,...) \
    if(this->get_this_log_level() >= lev || LogOutput::get()->level() >= lev || this->log_level >= lev) { \
        if(                                     \
            (                                   \
                ( LogOutput::get()->print_srcline() &&  lev >= INF )   \
                ||                          \
                LogOutput::get()->print_srcline_always()     \
            )                                            \
            &&                                           \
            !flag_test((lev).flags(),LOG_FLRAW)           \
          )                                              \
        { \
            LogOutput::get()->log2_w_name(lev,_FILE_,__LINE__,(hr()),(x),__VA_ARGS__); \
        } else { \
            LogOutput::get()->log_w_name(lev,(hr()),(x),__VA_ARGS__); \
        } \
    }

#define LN_LOGS_(lev,x) \
    if(this->get_this_log_level() >= lev || LogOutput::get()->level() >= lev || this->log_level() >= lev) { \
        if(                                     \
            (                                   \
                ( LogOutput::get()->print_srcline() &&  lev >= INF )   \
                ||                          \
                LogOutput::get()->print_srcline_always()     \
            )                                            \
            &&                                           \
            !flag_test((lev).flags(),LOG_FLRAW)           \
          )                                              \
        { \
            LogOutput::get()->log2_w_name(lev,_FILE_,__LINE__,(hr()),(x)); \
        } else { \
            LogOutput::get()->log_w_name(lev,(hr()),(x)); \
        } \
    }


#define T_LN_LOG_(name,interval,lev,x,...) \
    if(this->get_this_log_level() >= lev || LogOutput::get()->level() >= lev) { \
        if( ( LogOutput::get()->print_srcline() && LogOutput::get()->level() > INF ) || ( gLogOutput::et_logger()->print_srcline() && log_level() > INF ) || LogOutput::get()->print_srcline_always()) { \
            if(LogOutput::get()->click_timer(name,interval)) { \
                LN_LOG_(lev,x,__VA_ARGS__); \
            } \
        }\
    }

#define T_LN_LOGS_(name,interval,lev,x) \
    if(this->get_this_log_level() >= lev || LogOutput::get()->level() >= lev) { \
        if( ( LogOutput::get()->print_srcline() && LogOutput::get()->level() > INF ) || ( LogOutput::get()->print_srcline() && log_level() > INF ) || LogOutput::get()->print_srcline_always())) { \
            if(LogOutput::get()->click_timer(name,interval)) { \
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


#define PERIOD_START(interval) LogOutput::get()->periodic_start(interval);
#define PERIOD_END LogOutput::get()->periodic_end();


// takes argument of pointer to function which returns std::string, indicate object name.
#define DECLARE_LOGGING_OLD(get_name_func)  \
public:                                      \
    std::string hr() const { hr(get_name_func()); return hr_; }; \
    void hr(std::string const& s) const { \
       static std::mutex hr_mutex_; \
       std::scoped_lock<std::mutex> l(hr_mutex_);  \
       hr_ = s;   \
    } \
    static loglevel& log_level_ref() { return log_level(); } \
    static loglevel& log_level() { static loglevel l = NON; return l; };                             \
    loglevel& this_log_level_ref() { return this_log_level_; } \
    virtual loglevel get_this_log_level() const { return this_log_level_ > log_level() ? this_log_level_: log_level() ; }     \
    virtual void set_this_log_level(loglevel const& nl) { this_log_level_ = nl; }  \
private:                                                       \
    mutable std::string hr_;                                           \
    loglevel this_log_level_ = NON;


#define DECLARE_LOGGING(get_name_func)  \
public:                                      \
    std::string hr() const { hr(get_name_func()); return hr_; }; \
    void hr(std::string const& s) const { \
       std::scoped_lock<std::mutex> l(hr_lock_.mtx_);  \
       hr_ = s;   \
    } \
    static loglevel& log_level_ref() { return log_level(); } \
    static loglevel& log_level() { static loglevel l = NON; return l; };                             \
    loglevel& this_log_level_ref() { return this_log_level_; } \
    virtual loglevel get_this_log_level() const { return this_log_level_ > log_level() ? this_log_level_: log_level() ; }     \
    virtual void set_this_log_level(loglevel const& nl) { this_log_level_ = nl; }  \
    struct lock_struct {                    \
       lock_struct() = default;             \
       lock_struct(lock_struct const& r) {} \
       lock_struct& operator=(lock_struct const&) { return *this; } \
       std::mutex mtx_;                \
    };                                      \
private:                                                       \
    mutable std::string hr_;                                   \
    mutable lock_struct hr_lock_; \
    loglevel this_log_level_ = NON;



#define DECLARE_C_NAME(string_name)     \
private:                                \
    std::string name_ = string_name;   \
public:                                             \
    virtual std::string const& name() const  { return this->name_; }          \
    virtual const char* c_name() const { return this->name_.c_str(); }; \
    virtual void name(const char* n) { name_ = n; };        \
    virtual void name(std::string const& n) { name_ = n; };        \
    \
                    \
    virtual const std::string& class_name() const { static const std::string c(string_name); return c; } \
    virtual const char* c_class_name() const { return class_name().c_str(); } \
    /*virtual int size_of() { return sizeof (*this);  } */


#define DECLARE_DEF_TO_STRING \
    std::string to_string(int verbosity=iINF) const override { return this->class_name(); };


#endif //LOGGERMAC_HPP

