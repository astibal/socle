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

#ifndef BASETRAFLOG_HPP
#define BASETRAFLOG_HPP

#include <vars.hpp>

namespace socle {

    /** Encoding used for session secrets attached to packet captures. */
    enum class traffic_secret_format {
        tls_key_log,
    };

    class baseTrafficLogger {
        bool status_ {true};

    public:
        virtual ~baseTrafficLogger() = default;
        [[nodiscard]] inline bool status() const { return status_; }
        inline void status(bool b) { status_ = b; }

        /**
         * Write directional content. Packet-oriented loggers synthesize the
         * network and transport framing around these bytes.
         */
        virtual void write(side_t side, const buffer &b) = 0;
        virtual void write_left(buffer const& b) final {  if(status()) write(side_t::LEFT, b); };
        virtual void write_right(buffer const& b) final {  if(status()) write(side_t::RIGHT, b); };

        /**
         * Write one complete network-layer packet without synthesizing or
         * transforming its contents. Non-packet loggers ignore this record;
         * decorators may explicitly pass it to their wrapped logger.
         */
        virtual void write_packet(side_t, buffer const&) {}

        /** Attach decryption material to this capture when its format supports it. */
        virtual void write_secret(traffic_secret_format, buffer const&) {}

        virtual void write(side_t side, std::string const& s) = 0;
        void write_left(std::string const& s) { if(status()) write(side_t::LEFT, s); };
        void write_right(std::string const& s) { if(status()) write(side_t::RIGHT, s); };
    };


}


#endif //BASETRAFLOG_HPP
