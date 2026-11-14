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


#include <cstdlib>
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

    inline unsigned char arrow_from_side(side_t s) {
        if(s == side_t::RIGHT)
            return '<';

        return '>';
    }

    namespace raw {

        struct guard {
            guard() = delete;
            guard(std::function<void()> dter): deleter(dter) {}
            ~guard() {
                deleter();
            }

            guard(guard const& r) {
                if(&r != this) {
                    deleter = r.deleter;
                }
            }
            void operator=(guard const& v) {
                deleter = v.deleter;
            }

            std::function<void()> deleter;
        };

        template <typename T>
        struct var {
            var(T&& v, std::function<void(T&)> dter): value(std::move(v)), deleter(dter) {}
            var(var&) = delete;
            var& operator=(var const&) = delete;
            ~var() {
                deleter(value);
            }
            explicit operator T() { return value; }

            T value;
            std::function<void(T&)> deleter;
        };

        template <typename T>
        struct unique {
            unique(T&& v, std::function<void(T&)> dter): value(std::move(v)), deleter(dter) {}
            unique(unique &) = delete;

            ~unique() {
                if(own) deleter(value);
            }

            unique& operator=(unique const&) = delete;

            explicit operator T() { return value; }
            T release() { own = false; return value; }

            bool own = true;
            T value;
            std::function<void(T&)> deleter;
        };



        namespace deleter {

            template <typename PT>
            inline void free(PT const& ptr) {  ::free(ptr); }
            inline void fclose(FILE* const& f) { if (f) ::fclose(f); }
            inline void close(int const& f) { ::close(f); }

        }

        template<typename T> inline var<T> allocated(T ptr) {
            return var<T>(std::move(ptr), deleter::free<T>);
        }

        using file_var = var<FILE*>;
        template<typename T> inline file_var file(T ptr) {
            return var<T>(std::move(ptr), deleter::fclose);
        }

        template<typename From, typename To>
        struct dynamic_cast_cache {

            // mutable to not break const for owners; cache actually doesn't change any state!
            mutable std::pair<From*, To*> cached_cast = {nullptr, nullptr };
            To* cast(From* p) const {
                if(p != cached_cast.first) {
                    cached_cast.first = p;
                    cached_cast.second = dynamic_cast<To*>(p);
                }
                return cached_cast.second;
            }
        };
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
