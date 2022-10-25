#ifndef CONVERT_HPP_
#define CONVERT_HPP_

#include <optional>
#include <limits>
#include <stdexcept>
#include <typeinfo>
#include <type_traits>

namespace raw {

    template<typename T>
    std::size_t max_of() noexcept {
        static_assert(std::is_integral_v<T>, "integral type required.");

        return std::numeric_limits<T>::max();
    }
    template<typename T>
    std::size_t max_of(T const& t) noexcept {
        static_assert(std::is_integral_v<T>, "integral type required.");

        return std::numeric_limits<T>::max();
    }

    class cast_overflow : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
        explicit cast_overflow() noexcept : std::runtime_error("cast overflow") {};
        explicit cast_overflow(const char* what) noexcept : std::runtime_error(what) {};
    };

    template<typename T, typename U>
    inline std::optional<T> down_cast(std::optional<U> u) noexcept {
        static_assert(std::is_integral_v<T>, "integral type required.");
        static_assert(std::is_integral_v<U>, "integral type required.");

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
    inline std::optional<T> to_signed_cast(std::optional<U> u) {
        static_assert(std::is_integral_v<T>, "integral type required.");
        static_assert(std::is_integral_v<U>, "integral type required.");

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
    inline std::optional<T> to_signed_cast(U u) {
        return to_signed_cast<T>(std::make_optional<U>(u));
    }

    template<typename T, typename U>
    inline T try_to_signed_cast(U u) {
        static_assert(std::is_integral_v<T>, "integral type required.");
        static_assert(std::is_integral_v<U>, "integral type required.");

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
    inline std::optional<T> from_signed_cast(std::optional<U> u) {
        static_assert(std::is_integral_v<T>, "integral type required.");
        static_assert(std::is_integral_v<U>, "signed integral type required.");
        static_assert(std::is_signed_v<U>, "sign-cast not needed, converting only signed integrals");
        static_assert(sizeof(T) >= sizeof(U), "converting signed to unsigned for only for same, or larger size types");

        if(not u.has_value()) {
            return std::nullopt;
        }
        // if u is non-negative, we can convert or static-upcast
        else if(u >= static_cast<U>(0)) {
            return static_cast<T>(u.value());
        }
        else {
            return std::nullopt;
        }
    }

    template<typename T, typename U>
    inline std::optional<T> from_signed_cast(U u) {
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
}

#endif