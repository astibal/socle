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
#include <string>
#include <cstring>
#include <array>

#include "ltventry.hpp"
#include "display.hpp"
#include "log/logger.hpp"
#include "buffer.hpp"

#include <vars.hpp>
#include <convert.hpp>

using namespace socle;

LTVEntry::LTVEntry() {
	len_ = 0;
	id_ = 0;
	type_ = 0;
	data_ = nullptr;
	
	owner_ = true;
}

LTVEntry::LTVEntry(unsigned char id, unsigned char type, const char* str) {
	set_str(id,type,str);
}

LTVEntry::LTVEntry(unsigned char id, unsigned char type, uint32_t l) {
	set_num(id,type,l);
}


LTVEntry::~LTVEntry() {
	if (data_ != nullptr and owner() ) {
		delete[] data_;
	}
	
	for (auto ltve: contains()) {
		delete ltve;
	}
	
	contains().clear();
	data_ = nullptr;
}

// unpack packet structure and return number of bytes really "red". The rest should stay in the buffer 
// as the beginning of not yet received rest of the new package

int LTVEntry::unpack(uint8_t* buffer, unsigned int buflen) {

    auto const& log = get_log();

	_deb("LTVEntry::unpack:  --- process buffer 0x%x[%u], buffer owner=%d", buffer, (long) buflen,owner());
	
	
	// Read the length first, then require the complete fixed header.  A short
	// encoded length must never turn datalen() into a huge unsigned value.
	if (buffer == nullptr || buflen < sizeof(uint32_t)) {
		return -1;
	}
	_ext("stage1: can read length field");
	
	const auto wire_len = ltv_get_length(buffer);
	if (wire_len < ltv_header_size()) {
		return -1;
	}
	
	_ext("stage2: len detected: %d ", wire_len);
	_dum(hex_dump(buffer,4).c_str());
	if (buflen >= ltv_header_size()) {
		_dum(hex_dump(buffer+4,ltv_header_size()-4).c_str());
	}
		
	//return underflow if we should expect more data
	if (buflen < wire_len) {
		_deb("LTVEntry::unpack: buffer %x too short: %u, want to read %u bytes", buffer, buflen, wire_len);
		return 0;
	}

	if (buflen >= wire_len) {
		const bool own_buffer = owner();
		if (data_ != nullptr && own_buffer) {
			delete[] data_;
		}
		for (auto* entry: contains_) {
			delete entry;
		}
		contains_.clear();
		data_ = nullptr;
		len_ = wire_len;
		
		id_ = ltv_get_id(buffer);
		type_ = ltv_get_type(buffer);
		
		_ext("stage3: buffer of size %d could be fully read",len_);
		
		// if we are owning the buffer, fine, we will allocate.
		if ( owner () ) {
			_ext("LTVEntry::unpack: Allocating: buffer[%u] for new package data", len_);
			
			// allocate memory for the whole content of the packet (there could be more data, but we are dealing now only with first package)
			data_ = new uint8_t[len_];

			_ext(">> LTVEntry::unpack: orig.  buffer: 0x%x         | len,type,id: %u,%u,%u", (long)buffer, (unsigned int)len_, (unsigned int)type_, (unsigned int)id_);
			_ext(">> LTVEntry::unpack: target buffer:         0x%x | len %uB", (unsigned long)data_,len_);
			_ext(">> LTVEntry::unpack: copy   buffer: 0x%x -> 0x%x | len %uB", (unsigned long)buffer, (unsigned long)data_,len_);
			::memcpy(data_,buffer,len_);
			_ext("LTVEntry::unpack: memcpy: done");
		} else {
			
			// we are not owner of the buffer, so we can use pointer and create .
			_ext("LTVEntry::unpack: Allocating: shadow buffer[%u] in %x", len_, buffer);
			data_ = buffer;
		}


        auto hdr_size = raw::down_cast<uint32_t>(ltv_header_size()).value_or(raw::max_of<uint32_t>());
		if (type_ == typ::cont and len() > hdr_size) {
			// some stats
			unsigned int subentries=0;
		
			// start to dig all data inside
			unsigned int data_index = 0;
			unsigned int payload_len = len() - hdr_size;

			do {
				// all sub-entries should not allocate a single byte of memory => owner(false) will ensure this
				auto* l = new LTVEntry();
				l->owner(false);
				
				uint8_t* new_data = data() + data_index;
				
				int sub_red = l->unpack(new_data,payload_len);
				if (sub_red > 0) {
					contains().push_back(l);
					_deb("LTVEntry::unpack:   sub-entry[%u] at 0x%x[%u] | len %u", subentries,data(), (long)data_index,sub_red);
					
					data_index += sub_red;
					subentries++;
				} else {
					_war("LTVEntry::unpack:   sub-entry[%u] ERROR at 0x%x[%u] | len %u", subentries, data(), (long)data_index,sub_red);
					delete l;
					for (auto* entry: contains_) {
						delete entry;
					}
					contains_.clear();
					if (data_ != nullptr && own_buffer) {
						delete[] data_;
					}
					data_ = nullptr;
					len_ = 0;
					id_ = 0;
					type_ = 0;
					owner(own_buffer);
					return -1;
				}
				
				// this is correct place to finish the loop!
				if (data_index >= payload_len) {
					_deb("LTVEntry::unpack: last sub-entry[%u] finished at 0x%x[%u] | len %u", subentries, data(), (long)data_index, (long)payload_len);
					break;
				}
				
			} while (true);
		}
        else {
            _deb("LTVEntry::unpack: invalid header size");
        }
	}

	_dia("LTVEntry::unpack: finished buffer 0x%x[%u]", buffer, (long)buflen);
	return len_;
}

std::string LTVEntry::hr(int ltrim) {
	if (data_ == nullptr || len_ < ltv_header_size()) {
		return "LTVEntry::hr: uninitialized";
	}
	
	int tr = 0;
	if (ltrim > 0) {
		tr = ltrim + 4;
	}

	std::string p = std::string();
	for (int i=0; i<tr; i++) { p += ' ';}
	
	std::stringstream r;
	if (tr == 0) r << p + "LTVEntry::hr: packet human readable form:\n\n";
	r << p << "Package length : " << std::to_string((unsigned int)len_) <<'\n';
	r << p << "Package id     : " << std::to_string((unsigned int)id_) << '\n' ;
	r << p << "Package type   : " << std::to_string((unsigned int)type_) << '\n';
	r << p << "Data (" << std::to_string((unsigned int)len_-ltv_header_size()) + "B):\n";
	
	if (type_ == typ::num || type_ == typ::ip) {
		in_addr dd_addr = *(in_addr*)data();
        auto dd_int = tainted::var<uint32_t>(ntohl(*(uint32_t*)data()), tainted::any<uint32_t>);
		const char *ip = ::inet_ntoa((in_addr)dd_addr);
		
		r << + "Value (number) : " << std::to_string(dd_int) << " / " << ip << '\n' ;

	} else
	if (type_ == typ::str) {
		std::string s = std::string((char*)data(),(unsigned int)len_-ltv_header_size());
		r << p + "Value (string) : " << s << '\n' ;
	} else
    if (type_ == typ::cont) {
        r << p + "... " << std::to_string(contains().size()) << " element(s):\n";
	} else {
		r << hex_dump(data(),datalen(),ltrim,4);
	}
	
    if(tr) {
        r << "\n";
    }
	
	
	for (auto* ltve: contains()) {
		r << ltve->hr(tr+4);
	}
	
	return r.str();
}

std::string LTVEntry::data_str() const {
	if (data() == nullptr) return {};
	return std::string(reinterpret_cast<char*>(data()), datalen());
}

std::string LTVEntry::data_str_ip() const {
	if (datalen() != sizeof(in_addr)) {
		throw std::invalid_argument("invalid IPv4 data size");
	}
	in_addr dd_addr {};
	memcpy(&dd_addr, data(), sizeof(dd_addr));
	std::array<char, INET_ADDRSTRLEN> text {};
	if (::inet_ntop(AF_INET, &dd_addr, text.data(), text.size()) == nullptr) {
		throw std::invalid_argument("invalid IPv4 data");
	}
	return text.data();
}


void LTVEntry::clear() {
	if (data_ != nullptr && owner()) {
		delete[] data_;
	}
	for (auto* entry: contains_) {
		delete entry;
	}
	contains_.clear();
	data_ = nullptr;
	len(0);
	id(0);
	type(0);
	
	owner(false);
}


void LTVEntry::set_str(unsigned char i, unsigned char t, const char* str) {
	if (str == nullptr) {
		throw std::invalid_argument("string data must not be null");
	}
	
	clear();
	
	id_ = i;
	type_ = t;
	size_t data_len = strlen(str);
	data_ = new uint8_t[data_len+ltv_header_size()];
	owner(true);
	memcpy(data(),str,data_len);
	
	len_ = ltv_header_size() + data_len;
	
	ltv_set_length(buffer(),len());
	ltv_set_type(buffer(),type());
	ltv_set_id(buffer(),id());
	
}

void LTVEntry::set_bytes(unsigned char i, unsigned char t, const char* str, unsigned int size) {
	if (str == nullptr && size != 0) {
		throw std::invalid_argument("byte data must not be null");
	}
	
	clear();
	
	id_ = i;
	type_ = t;
	size_t data_len = size;
	data_ = new uint8_t[data_len+ltv_header_size()];
	owner(true);
	memset(data(),0,size);
	if (str != nullptr) {
		memcpy(data(),str,std::min<size_t>(strlen(str), data_len));
	}
	
	len_ = ltv_header_size() + data_len;
	
	ltv_set_length(buffer(),len());
	ltv_set_type(buffer(),type());
	ltv_set_id(buffer(),id());
	
}

void LTVEntry::set_num(unsigned char i, unsigned char t, uint32_t d) {
	
	clear();
	
	id_ = i;
	type_ = t;
	size_t data_len = sizeof(d);
	data_ = new uint8_t[data_len+ltv_header_size()];
	owner(true);
	
	const auto value = htonl(d);
	memcpy(data(), &value, sizeof(value));
	
	len_ = ltv_header_size() + data_len;
	
	ltv_set_length(buffer(),len());
	ltv_set_type(buffer(),type());
	ltv_set_id(buffer(),id());	
}

void LTVEntry::set_ip(unsigned char id, unsigned char type, const char* str) {
	struct in_addr inp{0};
	if (str == nullptr || inet_pton(AF_INET, str, &inp) != 1) {
		throw std::invalid_argument("invalid IPv4 address");
	}
	
	//what?? ip addresses are always hl and not honor network byte-order?
	set_num(id,type,ntohl(inp.s_addr));
}


void LTVEntry::container(unsigned char i) {
	clear();
	type(typ::cont);
	id(i);
	
	data_ = new uint8_t[ltv_header_size()];
	len_ = ltv_header_size();
	ltv_set_type(buffer(),type());
	ltv_set_id(buffer(),id());
	
	owner(true);
}


int LTVEntry::pack(::buffer* buf) {

    auto const& log = get_log();
	::buffer *b;
	
	// we need to know position where to store length of packed container!
	int length_pos = 0;
	bool this_is_owner = false;
	
	if (buf != nullptr) {
		b = buf; 
		length_pos = b->size();

	}
	else {
		b = new ::buffer();
		this_is_owner = true;
	}
	
	
	int sub_bytes = 0;
	if (type() == typ::cont) {
		if (buffer() == nullptr || buflen() < ltv_header_size()) {
			if (this_is_owner) delete b;
			return 0;
		}

		// Always rebuild containers from their fixed header.  Reusing the
		// previous packed payload made every repeated pack duplicate children.
		b->append(buffer(), ltv_header_size());
		
		for (auto* ltve: contains()) {
			sub_bytes += ltve->pack(b);
		}

		len(raw::down_cast<uint32_t>(ltv_header_size() + sub_bytes)
		        .value_or(raw::max_of<uint32_t>()));
		ltv_set_length(b->data()+(length_pos),len());	
		
		if(this_is_owner) {
			auto* packed = new uint8_t[b->size()];
			memcpy(packed, b->data(), b->size());
			if (data_ != nullptr && owner()) {
				delete[] data_;
			}
			data_ = packed;
			owner(true);
			delete b;
		}
		
		return len();
		
	} else {
		// this is not the container: return already allocated space
		if (buflen() > 0) {
			if (this_is_owner) {
				delete b;
				return buflen();
			}
			b->append(buffer(),buflen());
			_deb("LTVEntry::pack: scalar 0x%x packed in %d bytes", this, buflen());

			return buflen();
		} else {
			_war("LTVEntry::pack: warning - uninitialized LTVEntry at 0x%x", this);

			if(this_is_owner) {
			    delete b;   // coverity: 1407983  - this is tricky one. Delete 'b' iff is new allocation from this func.
			}
			return 0;
		} 
	}
}


LTVEntry* LTVEntry::search(const std::vector<int>& path) {

    auto const& log = get_log();
    _deb("LTVEntry::search:");

    LTVEntry* current = this;


    for (int path_element: path) {

        _deb("LTVEntry::search: token %d", path_element);

        bool found = false;

        for(auto* ltve: contains()) {
            if (ltve->id() == path_element) {
                current = ltve;
                _deb("LTVEntry::search: hit at 0x%x", ltve);
                found = true;
                break;
            }
        }

        if (! found) {
            _deb("LTVEntry::search: failed");
            return nullptr;
        }
    }

    _deb("LTVEntry::search: found match at 0x%x", current);
    return current;
}
