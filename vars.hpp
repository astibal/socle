//
// Created by astib on 15.07.21.
//

#ifndef SMITHPROXY_VARS_HPP
#define SMITHPROXY_VARS_HPP

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
}

#endif //SMITHPROXY_VARS_HPP
