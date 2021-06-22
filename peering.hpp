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

#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <variant>


template <typename T>
struct PeeringImpl {
    T* self;
    std::weak_ptr<PeeringImpl> other;
    PeeringImpl() = delete;
    PeeringImpl(T* owner) : self(owner) {}
    ~PeeringImpl() { detach(); }

    void attach(std::shared_ptr<PeeringImpl<T>> shr_other) {
        other = shr_other;
    };
    void detach() {
        other.reset();
    };

    mutable std::mutex lok;
};

template <typename T>
struct Peering {
    Peering(T* ow) : owner(ow) {};
    std::shared_ptr<PeeringImpl<T>> get() {
        if(not peer_) {
            peer_ = std::make_shared<PeeringImpl<T>>(owner);
        }
        return peer_;
    };
    std::shared_ptr<PeeringImpl<T>> fetch() {
        return peer_;
    };

    using ptrguard_t = std::pair<T*, std::unique_lock<std::mutex>>;
    ptrguard_t peer() {
        auto f = fetch();
        if(f) {
            auto shr = f->other.lock();
            if(shr) {
                T* ptr = shr->self;
                if(shr.use_count() == 1) {
                    return { nullptr, std::unique_lock<std::mutex>() };
                } else {
                    auto l_ = std::unique_lock(shr->lok);
                    return std::pair<T *, std::unique_lock<std::mutex>>{ptr, std::move(l_)};
                }
            }
        }
        return std::pair<T*,std::unique_lock<std::mutex>> { nullptr, std::unique_lock<std::mutex>() };
    }


    void attach(Peering<T>& other) {
        get()->attach(other.get());
    }

    void detach() {
        auto x = fetch();
        if(x) {
            x->detach();
        }
    }

private:
    T* owner;
    std::shared_ptr<PeeringImpl<T>> peer_{nullptr};
};

template <typename T>
struct PeeringGuard {
    PeeringGuard(Peering<T>& p) : peering(p) {};
    ~PeeringGuard() {
        auto p = peering.fetch();
        if(p) {
            auto l_ = std::unique_lock(p->lok);
            p->detach();
        }
    }
    Peering<T>& peering;
};



