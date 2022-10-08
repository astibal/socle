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

#include <log/loglevel.hpp>

namespace socle::log::level {

    const loglevel NON = loglevel(0, 0);
    const loglevel FAT = loglevel(1, 0);
    const loglevel CRI = loglevel(2, 0);
    const loglevel ERR = loglevel(3, 0);
    const loglevel WAR = loglevel(4, 0);
    const loglevel NOT = loglevel(5, 0);
    const loglevel INF = loglevel(6, 0);
    const loglevel DIA = loglevel(7, 0);
    const loglevel DEB = loglevel(8, 0);
    const loglevel DUM = loglevel(9, 0);
    const loglevel EXT = loglevel(10, 0);

    const loglevelmore LOG_EXTOPIC = loglevelmore(true, false);
    const loglevelmore LOG_EXEXACT = loglevelmore(true, true);

}

bool operator== (const loglevel& a, const loglevel& b) { return a.level() == b.level(); }
bool operator== (const loglevel& a, const unsigned int& b) { return a.level() == b; }
bool operator== (const unsigned int& a, const loglevel& b) { return a == b.level(); }


bool operator<= (const loglevel& a, const loglevel& b) { return a.level() <= b.level(); }
bool operator<= (const loglevel& a, const unsigned int& b) { return a.level() <= b; }
bool operator<= (const unsigned int& a, const loglevel& b) { return a <= b.level(); }


bool operator>= (const loglevel& a, const loglevel& b) { return a.level() >= b.level(); }
bool operator>= (const loglevel& a, const unsigned int& b) { return a.level() >= b; }
bool operator>= (const unsigned int& a, const loglevel& b) { return a >= b.level(); }


bool operator!= (const loglevel& a, const loglevel& b) { return a.level() != b.level(); }
bool operator!= (const loglevel& a, const unsigned int& b) { return a.level() != b; }
bool operator!= (const unsigned int& a, const loglevel& b) { return a != b.level(); }


bool operator> (const loglevel& a, const loglevel& b) { return a.level() > b.level(); }
bool operator> (const loglevel& a, const unsigned int& b) { return a.level() > b; }
bool operator> (const unsigned int& a, const loglevel& b) { return a > b.level(); }


bool operator< (const loglevel& a, const loglevel& b) { return a.level() < b.level(); }
bool operator< (const loglevel& a, const unsigned int& b) { return a.level() < b; }
bool operator< (const unsigned int& a, const loglevel& b) { return a < b.level(); }

loglevel operator-(const loglevel& a, const loglevel& b) { loglevel r = a; r.level(a.level() - b.level()); return r; }
loglevel operator-(const loglevel& a, const unsigned int& b) { loglevel r = a; r.level(a.level() - b); return r; }
loglevel operator+(const loglevel& a, const unsigned int& b) { loglevel r = a; r.level(a.level() + b); return r; }

