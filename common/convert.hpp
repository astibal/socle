#ifndef CONVERT_HPP_
#define CONVERT_HPP_

#include <optional>
#include <limits>
#include <stdexcept>
#include <typeinfo>
#include <type_traits>

namespace socle::raw {

    // get max value of given template parameter type
    template<typename T>
    std::size_t max_of() noexcept {
        static_assert(std::is_integral_v<T>, "integral type required.");

        return std::numeric_limits<T>::max();
    }

    // get max value of given argument type - use with target variable to deduce type automatically
    template<typename T>
    std::size_t max_of([[maybe_unused]] T const& t) noexcept {
        static_assert(std::is_integral_v<T>, "integral type required.");

        return std::numeric_limits<T>::max();
    }

    // `cast_overflow` thrown only from try_* functions
    class cast_overflow : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
        explicit cast_overflow() noexcept : std::runtime_error("cast overflow") {};
    };


    // down_cast larger size parameter value into smaller-size returned value.
    template<typename T, typename U>
    inline std::optional<T> down_cast(std::optional<U> u) noexcept {
        static_assert(std::is_integral_v<T> and std::is_integral_v<U>, "integral type required.");
        static_assert(
                      (std::is_signed_v<T> and std::is_signed_v<U>) or
                      (not std::is_signed_v<T> and not std::is_signed_v<U>)
                      , "converted values must have the same sign-ness");

        if(not u.has_value()) {
            return std::nullopt;
        }
        else if (u.value() > std::numeric_limits<T>::max() or u.value() < std::numeric_limits<T>::min()) {
            return std::nullopt;
        }
        else {
            return static_cast<T>(u.value());
        }
    }

    template<typename T, typename U>
    inline std::optional<T> down_cast(U u) noexcept {
        return down_cast<T>(std::make_optional<U>(u));
    }


    template<typename T, typename U>
    inline T try_down_cast(U u) {
        static_assert(std::is_integral_v<T>, "integral type required.");
        static_assert(std::is_integral_v<U>, "integral type required.");

        if (u > std::numeric_limits<T>::max() or u < std::numeric_limits<T>::min()) {
            throw cast_overflow("bad_cast: out of target type bounds");
        }
        else {
            return static_cast<T>(u);
        }
    }

    template<typename T, typename U>
    inline std::optional<T> to_signed_cast(std::optional<U> u) noexcept {
        static_assert(std::is_integral_v<T> and std::is_integral_v<U>, "integral types required.");

        if(not u.has_value()) {
            return std::nullopt;
        }
        else if(u <= std::numeric_limits<T>::max()) {
            return static_cast<T>(u.value());
        }
        else if(u >= std::numeric_limits<T>::min()) {
            return static_cast<T>(u.value() - std::numeric_limits<T>::min()) + std::numeric_limits<T>::min();
        }
        else {
            return std::nullopt;
        }
    }

    template<typename T, typename U>
    inline std::optional<T> to_signed_cast(U u) noexcept {
        return to_signed_cast<T>(std::make_optional<U>(u));
    }

    template<typename T, typename U>
    inline T try_to_signed_cast(U u) {
        static_assert(std::is_integral_v<T> and std::is_integral_v<U>, "integral types required.");

        if(u <= std::numeric_limits<T>::max()) {
            return static_cast<T>(u.value());
        }
        else if(u >= std::numeric_limits<T>::min()) {
            return static_cast<T>(u - std::numeric_limits<T>::min()) + std::numeric_limits<T>::min();
        }
        else {
            throw cast_overflow("bad_cast: out of target type bounds");
        }
    }

    template<typename T, typename U>
    inline std::optional<T> from_signed_cast(std::optional<U> u) noexcept {
        static_assert(std::is_integral_v<T> and std::is_integral_v<U>, "integral types required.");
        static_assert(std::is_signed_v<U>, "converting only signed integrals");
        static_assert(sizeof(T) >= sizeof(U), "converting signed to unsigned for only for same, or larger size types");

        if(not u.has_value()) {
            return std::nullopt;
        }
        // if u is non-negative, we can convert or static-upcast
        else if(u.value() >= static_cast<U>(0)) {
            return static_cast<T>(u.value());
        }
        else {
            return std::nullopt;
        }
    }

    template<typename T, typename U>
    inline std::optional<T> from_signed_cast(U u) noexcept {
        return from_signed_cast<T>(std::make_optional<U>(u));
    }


    template<typename T, typename U>
    inline std::optional<T> try_from_signed_cast(U u) {
        static_assert(std::is_integral_v<T>, "integral type required.");
        static_assert(std::is_integral_v<U>, "integral type required.");
        static_assert(std::is_signed_v<U>, "sign-cast not needed, converting only signed integrals");
        static_assert(sizeof(T) >= sizeof(U), "converting signed to unsigned for only for same, or larger size types");

        if(u >= static_cast<U>(0)) {
            return static_cast<T>(u);
        }
        else {
            throw cast_overflow("bad_cast: casting negative to unsigned value");
        }
    }


    template <typename U>
    inline auto sign_remove(U u) noexcept -> std::optional<std::make_unsigned_t<U>> {
        static_assert(std::is_integral_v<U> and std::is_signed_v<U>);
        return from_signed_cast<std::make_unsigned_t<U>>(u);
    }

    template <typename U>
    inline auto try_sign_remove(U u) -> std::optional<std::make_unsigned_t<U>> {
        static_assert(std::is_integral_v<U> and std::is_signed_v<U>);
        return try_from_signed_cast<std::make_unsigned_t<U>>(u);
    }

    template <typename U>
    inline auto sign_add(U u) noexcept -> std::optional<std::make_signed_t<U>> {
        static_assert(std::is_integral_v<U> and std::is_unsigned_v<U>);
        return to_signed_cast<std::make_signed_t<U>>(u);
    }

    template <typename U>
    inline auto try_sign_add(U u) -> std::optional<std::make_signed_t<U>> {
        static_assert(std::is_integral_v<U> and std::is_unsigned_v<U>);
        return try_to_signed_cast<std::make_signed_t<U>>(u);
    }

    template <typename T, typename U>
    inline auto down_cast_signed(U u) noexcept -> std::optional<T> {
        return down_cast<T>(sign_remove(u));
    }

    template <typename T, typename U>
    inline auto down_cast_signed(std::optional<U> u) noexcept -> std::optional<T> {
        return down_cast<T>(sign_remove(u));
    }

    template <typename T, typename U>
    inline auto try_down_cast_signed(std::optional<U> u) -> std::optional<T> {
        return try_down_cast<T>(sign_remove(u));
    }


    template <typename T, typename U>
    struct greater_trait {
            constexpr static bool value = sizeof(T) > sizeof(U);
    };

    template <typename T, typename U>
    struct signness_trait {
        constexpr static bool value = (std::is_signed_v<T> and std::is_signed_v<U>) or
                                      (std::is_unsigned_v<T> and std::is_unsigned_v<U>);
    };


    template <
            typename T, typename U,
            typename = std::enable_if<greater_trait<T,U>::value>,
            typename = std::enable_if<signness_trait<T,U>::value>,
            typename = std::enable_if<std::is_arithmetic_v<T>>,
            typename = std::enable_if<std::is_arithmetic_v<U>>
    >
    T up_cast(U u) {
        return static_cast<T>(u);
    }
}

#endif