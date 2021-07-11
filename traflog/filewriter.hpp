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

#ifndef FILEWRITER_HPP
#define FILEWRITER_HPP

#include <string>
#include <iostream>
#include <fstream>
#include <memory>

#include <traflog/basefilewriter.hpp>

namespace socle {

    class fileWriter : public baseFileWriter {

        std::unique_ptr<std::ofstream> writer_;
        bool opened_;
        std::string filename_;

    public:
        explicit fileWriter() : writer_(nullptr), opened_(false) {};

        bool opened() override { return opened_; }
        inline void opened(bool b) { opened_ = b; }

        [[nodiscard]] inline std::string const& filename() const { return filename_; };

        std::size_t write(std::string const&fnm, std::string const& str) override;
        bool open(std::string const& fnm) override;
        bool close(std::string const& fnm) override;

        virtual void close();
        bool flush(std::string const& fnm) override;
    };

}

#endif //FILEWRITER_HPP
