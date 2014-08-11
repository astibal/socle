#ifndef DISPLAY_HPP
#define DISPLAY_HPP

#include <string>

std::string string_format(const std::string fmt, ...);
std::string hex_dump(unsigned char *data, int size, unsigned int=0,unsigned char=0);

#endif