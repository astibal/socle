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
        struct can_upcast {
            constexpr static bool value = (sizeof(T) > sizeof(U) or
                                           (sizeof(T) == sizeof(U) and
                                            (std::is_unsigned_v < T > and std::is_signed_v < U > ))
            );
        };

        template<typename T, typename U>
        struct can_cast {
            constexpr static bool value = (sizeof(T) > sizeof(U) or
                                           (sizeof(T) == sizeof(U) and
                                            (std::is_unsigned_v < T > and std::is_signed_v < U > )) or
                                           std::is_same_v < T, U >
            );
        };


        template<typename T, typename U>
        struct same_size {
            constexpr static bool value = sizeof(T) == sizeof(U);
        };

        template<typename T, typename U>
        struct same_signness {
            constexpr static bool value = (std::is_signed_v < T > and std::is_signed_v < U > ) or
                                          (std::is_unsigned_v < T > and std::is_unsigned_v < U > );
        };
    }

    template<typename T, typename = std::enable_if <std::is_arithmetic_v<T>>>
    class number {

    public:
        template<typename U, typename = std::enable_if_t<std::is_arithmetic_v<U>>>
        number(U u) {
            if constexpr (traits::can_cast<T, U>::value == true) {
                value_ = u;
            } else {
                from(u);
            }
        }

        template<typename U>
        number(number<U> n) {
            if (n.has_value()) {
                if constexpr (traits::can_cast<T, U>::value == true) {
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
        number<T> &from(U const &u) {
            auto result = create(u);
            if (result.has_value()) value_ = result.value();
            else value_ = std::nullopt;

            return *this;
        }

        template<typename U, typename = std::enable_if_t<std::is_arithmetic_v<U>>>
        static number<T> create(U b) {
            if (traits::same_signness<T, U>::value and traits::same_size<T, U>::value) {
                return number<T>(static_cast<T>(b));
            } else if constexpr (traits::can_upcast<T, U>::value) {
                return number<T>(static_cast<T>(b));
            } else if constexpr (std::is_unsigned_v < T > and std::is_signed_v < U >) {
                auto temp_optional = down_cast<T>(sign_remove(b));
                return temp_optional.has_value() ? number<T>(temp_optional.value()) : number<T>();
            } else {
                auto temp_optional = down_cast<T>(b);
                return temp_optional.has_value() ? number<T>(temp_optional.value()) : number<T>();
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

    using n8 = number<uint8_t>;
    using sn8 = number<int8_t>;

    using n16 = number<uint16_t>;
    using sn16 = number<int16_t>;

    using n32 = number<uint32_t>;
    using sn32 = number<int32_t>;

    using n64 = number<uint64_t>;
    using sn64 = number<int64_t>;
}

#endif