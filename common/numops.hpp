// SPDX-License-Identifier:        GPL-2.0+

#ifndef NUMOPS_HPP_
#define NUMOPS_HPP_

#include <number.hpp>
#include <convert.hpp>

#include <limits>
#include <optional>
#include <cmath>

namespace socle::raw {

    template<typename T, typename = std::enable_if_t<std::is_arithmetic_v<T>>>
    auto safe_add_(T a, T b) -> number<T> {

        if constexpr (std::is_signed_v<T>) {
            if(a < 0 and b < 0) {
                if (std::abs(b) > (std::numeric_limits<T>::max() - abs(a))) {
                    return number<T>::nan;
                }
            }
            else if (a > 0 and b > 0) {
                // treat positive values separately to avoid unwanted promotions
                if (b > (std::numeric_limits<T>::max() - a)) {
                    return number<T>::nan;
                }
            }
        }
        else if (b > (std::numeric_limits<T>::max() - a)) {
            return number<T>::nan;
        }

        return number<T>(static_cast<T>(a + b));
    }

    template<typename T, typename... Ts>
    using _all_same = std::enable_if_t<std::conjunction_v<std::is_same<T, Ts>...>>;

    template <typename T, typename... Ts, typename = _all_same<T, Ts...>>
    number<T> safe_add(T t, Ts ...vals) {

        static_assert(std::is_arithmetic_v<T>, "safe_add: accepting only arithmetic parameters");

        if constexpr (sizeof...(vals) == 1) {
            return safe_add_(t, vals...);
        } else {
            auto r = safe_add(vals...);
            if(not r.has_value()) return number<T>();

            return safe_add_(t, r.value());
        }
    }

    namespace predicates {

        template<typename T>
        bool is_negative(number<T> const& value) {
            if constexpr (std::is_signed_v<T>)
            {
                if (value.valid())
                {
                    return value.value() < 0;
                }
                return false;
            }
            return false;
        }
    }

    namespace operators {

        template<typename T>
        number<T> operator+(number<T> a, number<T> b) {
            if(not a.has_value() or not b.has_value()) {
                return number<T>();
            }
            else {
                return safe_add_(a.value(), b.value());
            }
        }
        template<typename T>
        number<T> operator+(number<T> a, T b) {
            if(not a.has_value()) {
                return number<T>();
            }
            else {
                return safe_add_(a.value(), b);
            }
        }

        template<typename T, typename U,
                typename = std::enable_if_t<std::is_arithmetic_v<T>>,
                typename = std::enable_if_t<std::is_arithmetic_v<U>>>
        number<T> operator+(number<T> a, number<U> b) {
            if(not a.valid() or not b.valid()) {
                return number<T>::nan;
            }
            if constexpr(traits::can_static_cast<T,U>::value)
            {
                return safe_add_(a.value(), static_cast<T>(b.value()));
            }
            else if constexpr(std::is_unsigned_v<T> and std::is_signed_v<U>)
            {
                auto downcasted = down_cast<T>(sign_remove(b.value()));
                return downcasted.has_value() ?  safe_add_(a.value(), downcasted.value()) : number<T>();
            }
            else
            {
                auto downcasted = down_cast<T>(b.value());
                return downcasted.has_value() ? safe_add_(a.value(),downcasted.value()) : number<T>();
            }
        }

        template<typename T, typename U,
                typename = std::enable_if_t<std::is_arithmetic_v<T>>,
                typename = std::enable_if_t<std::is_arithmetic_v<U>>>

        number<T> operator-(number<T> a, number<U> b) {
            if(a.is_nan() or b.is_nan()) {
                return number<T>::nan;
            }
            else if(predicates::is_negative(b)) {
                auto compat_b = number<T>::create(b.value());
                if(compat_b.is_nan()) return number<T>::nan;

                if(a.value() <= std::numeric_limits<T>::max() - b.value()) {
                    // we are in limits, static cast is safe
                    return number<T>(static_cast<T>(a.value() - b.value()));
                }
                else {
                    return number<T>::nan;
                }
            }
            else {
                auto compat_b = number<T>::create(b.value());
                if(compat_b.is_nan()) return number<T>::nan;

                if(a.value() >= std::numeric_limits<T>::min() + compat_b.value()) {
                    // we are in limits, static cast is safe
                    return number<T>(static_cast<T>(a.value() - b.value()));
                }
                else {
                    return number<T>::nan;
                }
            }
        }
    }
}

#endif