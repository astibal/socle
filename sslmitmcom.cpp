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

#include <sslmitmcom.hpp>

template<> std::string baseSSLMitmCom<baseSSLCom<UDPCom>>::sslmitmcom_name_ = "ssl";
template<> std::string baseSSLMitmCom<baseSSLCom<UDPCom>>::sslmitmcom_insp_name_ = "ssl+insp";
template<> std::string baseSSLMitmCom<baseSSLCom<TCPCom>>::sslmitmcom_name_ = "ssl";
template<> std::string baseSSLMitmCom<baseSSLCom<TCPCom>>::sslmitmcom_insp_name_ = "ssl+insp";
