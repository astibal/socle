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

#ifndef STRINGOPS_HPP
#define STRINGOPS_HPP

#include <string>
#include <vector>

// return a string from tag string:
// "+a+b+c" is {"a", "b", "c"}
// "+a+b-a" is {"b"}
// ... with caveat if "=" is present in the string, at that point map is reset

// retrieve tags from a single string
std::vector<std::string> string_tags(std::string const& str);

// update existing vector of strings with an update string
void string_tags_update(std::vector<std::string>& existing, std::string const& str);

#endif //STRINGOPS_HPP
