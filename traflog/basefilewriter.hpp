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


#ifndef BASEFILEWRITER_HPP
#define BASEFILEWRITER_HPP

#include <string>

namespace socle {

    class baseFileWriter {
    public:
        // returns number of written bytes in str written into fnm
        virtual std::size_t write (std::string const &fnm, std::string const &str) = 0;

        // unguaranteed flush - stream will be flushed to disk if possible
        virtual bool flush (std::string const &fnm) = 0;

        // open the file
        virtual bool open (std::string const &fnm) = 0;

        // close the file
        virtual bool close (std::string const &fnm) = 0;

        // is this writer opened?
        virtual bool opened () = 0;

        virtual ~baseFileWriter () = default;
    };
};

#endif //BASEFILEWRITER_HPP
