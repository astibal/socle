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

#ifndef VARS_HPP
#define VARS_HPP


#include <cstdio>
#include <unistd.h>
#include <functional>

namespace socle {

    enum class side_t { LEFT, RIGHT };

    inline side_t to_side(unsigned char s) {
        if(s == 'R' or s == 'r')
            return side_t::RIGHT;

        return side_t::LEFT;
    }

    inline unsigned char from_side(side_t s) {
        if(s == side_t::RIGHT)
            return 'R';

        return 'L';
    }

    namespace raw {
        template <class T>
        struct lax {
            lax() = delete;
            lax(T&& v, std::function<void(T&)> dter): value(std::move(v)), deleter(dter) {}
            lax(T v, std::function<void(T&)> dter): value(v), deleter(dter) {}

            ~lax() {
                deleter(value);
            }

            lax(lax& r) {
                if(&r != this) {
                    deleter(value);
                    value = r.value;
                }
            }
            void operator=(lax const& v) {
                deleter(value);
                value = v;
            }

            T value;
            std::function<void(T&)> deleter;
        };


        template <typename T>
        struct var {
            var(T&& v, std::function<void(T&)> dter): value(std::move(v)), deleter(dter) {}
            var(var&) = delete;
            ~var() {
                deleter(value);
            }

            T value;
            std::function<void(T&)> deleter;
        };

        template <typename T>
        struct unique {
            unique(T&& v, std::function<void(T&)> dter): value(std::move(v)), deleter(dter) {}

            unique& operator=(unique const&) = delete;
            unique(unique &) = delete;

            ~unique() {
                deleter(value);
            }

            T value;
            std::function<void(T&)> deleter;
        };



        struct call_scope_exit {
            explicit call_scope_exit(std::function<void()> cb): cb_(cb) {}

            call_scope_exit& operator=(call_scope_exit const&) = delete;
            call_scope_exit(call_scope_exit &) = delete;

            ~call_scope_exit() {
                cb_();
            }

            std::function<void()> cb_;
        };

        template <typename T>
        struct watch_scope_exit {
            explicit watch_scope_exit(T& ref, std::function<void(T&)> cb): value_(ref), cb_(cb) {}

            watch_scope_exit& operator=(watch_scope_exit const&) = delete;
            watch_scope_exit(watch_scope_exit &) = delete;

            ~watch_scope_exit() {
                cb_(value_);
            }

            T& value_;
            std::function<void(T&)> cb_;
        };


        namespace deleter {

            template <typename PT>
            inline void free(PT const& ptr) {  ::free(ptr); }
            inline void fclose(FILE* const& f) { ::fclose(f); }
            inline void close(int const& f) { ::close(f); }

        }

        template<typename T> inline var<T> allocated(T ptr) {
            return var<T>(std::move(ptr), deleter::free<T>);
        }
    }

    namespace tainted {
        template<typename T>
        inline T var(T const& value, std::function<T (T const&)> filter) noexcept {
            return filter(value);
        }

        template<typename T>
        T any(T const& v) { return v; }
    }
}

#endif //VARS_HPP
