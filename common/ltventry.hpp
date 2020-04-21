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

#ifndef LTVENTRY_HPP
#define LTVENTRY_HPP

#include <string>
#include <vector>

#include <cstdint>
#include <arpa/inet.h>

#include <buffer.hpp>
#include <log/logan.hpp>

inline uint32_t ltv_get_length(uint8_t const* data) { return ntohl(*((uint32_t*)data)); }
inline void ltv_set_length(uint8_t* const data, uint32_t l) { *((uint32_t*)data) = htonl(l); }

inline uint8_t  ltv_get_id(uint8_t* const data) { return ((uint8_t*)data)[4]; }
inline void  ltv_set_id(uint8_t* const data, uint8_t i) { ((uint8_t*)data)[4] = i; }

inline uint8_t  ltv_get_type(uint8_t* const data) { return ((uint8_t*)data)[5]; }
inline void  ltv_set_type(uint8_t* const data, uint8_t t) { ((uint8_t*)data)[5] = t; }


inline uint8_t* ltv_get_data_ptr(uint8_t* const data) { return &((uint8_t*)data)[6]; }

inline size_t  ltv_header_size() { return (sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t)); }

class buffer;

class LTVEntry
{
	std::vector<LTVEntry*> contains_;
	
	uint32_t  len_{0};
	unsigned char id_{0};
	unsigned char type_{0};
	uint8_t* data_{nullptr};
	
	bool owner_ {true};
	

public:
	enum typ { auth=1, num=3, ip=3, str=5, cont=6 };	
	LTVEntry();
    LTVEntry(unsigned char id, unsigned char type, const char*);
	LTVEntry(unsigned char id, unsigned char type, unsigned long);
	
	virtual ~LTVEntry();
	
	[[nodiscard]] inline bool owner() const { return owner_; }
	inline void owner(bool o) { owner_ = o; }

    [[nodiscard]] inline unsigned char id() const { return id_; }
    [[nodiscard]] inline unsigned char type() const { return type_; }
    [[nodiscard]] inline uint32_t len() const { return len_; }

	inline void id(unsigned char i) { id_ = i; }
	inline void type(unsigned char t){ type_ = t; }
	inline void len(uint32_t l) { len_ = l; }

	inline std::vector<LTVEntry*>& contains() { return contains_; }
	inline void add(LTVEntry* e) { contains().push_back(e); }
	
	inline int size() { return contains().size(); }
	inline LTVEntry* at(int i) {
		if (i < size()) {
			return contains().at(i);
		} else {
			return nullptr;
		}
	}
	inline LTVEntry* operator[] (int i) {
		return at(i);
	}

    [[nodiscard]] inline uint8_t* data() const { return ltv_get_data_ptr(data_); }
    [[nodiscard]] inline size_t datalen() const { return len() -ltv_header_size(); };

    [[nodiscard]] inline uint8_t* buffer() const { return data_; }
    [[nodiscard]] inline uint32_t buflen() const { return len(); }
	
	int unpack(uint8_t* buffer,unsigned int buflen);
	
	void clear();
	void set_str(unsigned char id,unsigned char type,const char*);
	void set_bytes(unsigned char id,unsigned char type,const char*,unsigned int len);
	void set_ip(unsigned char id,unsigned char type,const char*);
	void set_num(unsigned char id,unsigned char type,uint32_t);
	void container(unsigned char id);

    [[nodiscard]] inline unsigned long data_int() const { return ntohl(*(uint32_t*)data()); }
    inline void write_int(uint32_t d) {
        if(datalen() >= 4) { *(uint32_t*)data() = htonl(d); }
        else { throw std::invalid_argument("data size too small to write uint32"); }
    }

    [[nodiscard]] std::string data_str() const;
    [[nodiscard]] std::string data_str_ip() const;
	
 	int pack(::buffer *buf=nullptr);
	
	//FIXME: return single string (hr = human readable)
	std::string hr(int=0);
	
    LTVEntry* search(const std::vector<int>&);

    static logan_lite& get_log() {
         static logan_lite l = logan_lite("internal.ltv");

         return l;
    }
};

#endif // LTVENTRY_HPP
