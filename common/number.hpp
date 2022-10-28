// SPDX-License-Identifier:        GPL-2.0+

#ifndef NUMBER_HPP_
#define NUMBER_HPP_

#include <convert.hpp>

#include <limits>
#include <optional>
#include <cmath>


namespace socle::raw {

    namespace traits {

        template<typename T, typename U>
        struct same_size {
            constexpr static bool value = sizeof(T) == sizeof(U);
        };

        template<typename T, typename U>
        struct fitting_size {
            constexpr static bool value = sizeof(T) >= sizeof(U);
        };

        template<typename T, typename U>
        struct same_signness {
            constexpr static bool value = ((std::is_signed_v < T > and std::is_signed_v < U > ) or
                                          (std::is_unsigned_v < T > and std::is_unsigned_v < U > ));
        };

        // use when we can directly copy values and keeping number sign-ness
        template<typename T, typename U>
        struct can_static_cast {
            constexpr static bool value = same_signness<T,U>::value and fitting_size<T,U>::value;
        };
    }

    template<typename T, typename = std::enable_if <std::is_arithmetic_v<T>>>
    class number {

    public:

        using type = T;

        template<typename U,
                std::enable_if_t<std::is_arithmetic_v<U>, bool> = true>
        number(U u) noexcept {
            if constexpr (traits::can_static_cast<T, U>::value == true) {
                value_ = u;
            }
            else {
                from(u);
            }
        }

        template<typename U
                //std::enable_if_t<traits::same_signness<T,U>::value, bool> = true
                >
        number(number<U> n) {
            if (n.has_value()) {
                if constexpr (traits::can_static_cast<T, U>::value == true) {
                    value_ = n.value();
                } else {
                    from(n.value());
                }
            }
        }


        number() = default;

        auto& opt() { return value_; }
        auto const& opt() const { return value_; }

        T value() const { return value_.value(); }

        T value_or(T def) const { return value_.value_or(def); }

        bool has_value() const { return value_.has_value(); }



        template<typename U, typename = std::enable_if_t<std::is_arithmetic_v<U>>>
        void from(U const &u) {
            auto result = create(u);
            if (result.has_value()) {
                value_ = result.value();
            }
            else {
                value_ = std::nullopt;
            }
        }

        template<typename U, typename = std::enable_if_t<std::is_arithmetic_v<U>>>
        static number<T> create(number<U> b) {
            return b.valid() ? create(b.value()) : number<T>::nan;
        }

        template<typename U, typename = std::enable_if_t<std::is_arithmetic_v<U>>>
        static number<T> create(U b) {
            if (traits::same_signness<T, U>::value and traits::same_size<T, U>::value) {
                return number<T>(static_cast<T>(b));
            } else if constexpr (traits::can_static_cast<T, U>::value) {
                return number<T>(static_cast<T>(b));
            } else if constexpr (std::is_unsigned_v < T > and std::is_signed_v < U >) {
                auto temp_optional = down_cast<T>(sign_remove(b));
                return temp_optional.has_value() ? number<T>(temp_optional.value()) : number<T>();
            } else {
                auto temp_optional = down_cast<T>(b);
                return temp_optional.has_value() ? number<T>(temp_optional.value()) : number<T>();
            }
        }

        template<typename U, typename = std::enable_if_t<std::is_arithmetic_v<U>>>
        number<U> promote() const {
            if constexpr (traits::can_static_cast<U, T>::value) {
                return number<U>(value());
            }
            else {
                return number<U>::nan;
            }
        }

        template<typename U, typename = std::enable_if_t<std::is_arithmetic_v<U>>>
        number<U> to_signed() const {
            auto temp_downcasted = to_signed_cast<U>(value());

            if(temp_downcasted.has_value()) {
                return number<U>(temp_downcasted.value());
            }
            else {
                return number<U>::nan;
            }
        }


        operator std::optional<T> () { return value_; }

        bool valid() const { return opt().has_value(); }
        bool is_nan() const { return not opt().has_value(); }

        bool is(T const& compare_to) const noexcept { if(valid()) return (opt().value() == compare_to); return false;  }
        bool is(number<T> const& compare_to) const noexcept { if(valid() and compare_to.valid()) return (opt().value() == compare_to.value()); return false;  }

        static inline number<T> nan = number<T>();
    private:
        std::optional <T> value_;
    };

    using n8_t = number<uint8_t>;
    using sn8_t = number<int8_t>;

    using n16_t = number<uint16_t>;
    using sn16_t = number<int16_t>;

    using n32_t = number<uint32_t>;
    using sn32_t = number<int32_t>;

    using n64_t = number<uint64_t>;
    using sn64_t = number<int64_t>;
}

#endif