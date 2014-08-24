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

#define D_(x) if(lout.level() >= DEB) { (x); }

#define LOG_(lev,x,...) \
	if(lout.level() >= lev) { \
		lout.log(lev,(x),__VA_ARGS__); \
	}

#define LOGS_(lev,x) \
	if(lout.level() >= lev) { \
		lout.log(lev,(x)); \
	}

#define T_LOG_(name,interval,lev,x,...) \
	if(lout.level() >= lev) { \
		if(lout.click_timer(name,interval)) { \
			LOG_(lev,x,__VA_ARGS__); \
		} \
	}

#define T_LOGS_(name,interval,lev,x) \
	if(lout.level() >= lev) { \
		if(lout.click_timer(name,interval)) { \
			LOGS_(lev,x); \
		} \
	}

	
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


#define PERIOD_START(interval) lout.periodic_start(interval);
#define PERIOD_END lout.periodic_end();

struct timer {
	time_t last;
	unsigned int timeout;
};

typedef struct timer timer_tt;

class logger {
protected:
	unsigned int level_;
	unsigned int period_ = 5;
	time_t last_period = 0;
	bool last_period_status = false;
	
	mutable std::mutex mtx_lout;
	
	std::map<std::string,timer_tt> timers;
	mutable std::mutex mtx_timers;
	
     std::ostream* target_ = NULL;
public:
	logger() { level_=0; period_ =5; };
    ~logger() { if(target_) { target()->flush(); delete target_; } };
	
	void level(unsigned int l) { level_ = l; };
	inline unsigned int level(void) const { return level_; };
	
	bool click_timer(std::string, int);
	
	
 	std::ostream* target() { return target_; }
 	void target(std::ostream* o) { target_ = o; }
	
	std::string format(const std::string, ...);
	void log(unsigned int, const std::string, ...);
	
	inline unsigned int period() { return period_; }
	inline void period(unsigned int p) { period_ = p; }
	
    bool periodic_start(unsigned int s);	
	bool periodic_end();
};

extern logger lout;

#endif // LOGGER_HPP
