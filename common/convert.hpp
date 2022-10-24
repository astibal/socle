#ifndef CONVERT_HPP_
#define CONVERT_HPP_

#include <optional>
#include <limits>

namespace raw {

    template<typename T, typename U>
    inline std::optional<T> down_cast(std::optional<U> u) {
        if(not u.has_value()) {
            return std::nullopt;
        }
        else if (u > std::numeric_limits<T>::max() or u < std::numeric_limits<T>::min()) {
            return std::nullopt;
        }
        else {
            return static_cast<T>(u.value());
        }
    }

    template<typename T, typename U>
    inline std::optional<T> down_cast(U u) {
        return down_cast<T>(std::make_optional<U>(u));
    }



    template<typename T, typename U>
    inline std::optional<T> to_signed_cast(std::optional<U> u) {
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
    inline std::optional<T> from_signed_cast(std::optional<U> u) {
        if(not u.has_value()) {
            return std::nullopt;
        }
        else if(u <= std::numeric_limits<T>::max() and u >= static_cast<U>(0)) {
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

}

#endif