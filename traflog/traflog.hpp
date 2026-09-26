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

#ifndef TRAFLOG_HPP
#define TRAFLOG_HPP

#include <traflog/threadedpoolwriter.hpp>
#include <traflog/filewriter.hpp>
#include <baseproxy.hpp>


#include <traflog/basetraflog.hpp>

namespace socle::traflog {

std::string traflog_dir_key(baseProxy* proxy_);
std::string traflog_file_key(baseProxy* proxy_, char side);




}

#endif
