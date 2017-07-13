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

#include "ltventry.hpp"
#include "display.hpp"
#include "logger.hpp"
#include "buffer.hpp"

LTVEntry::LTVEntry() {
	len_ = 0;
	id_ = 0;
	type_ = 0;
	data_ = NULL;
	
	owner_ = true;
}

LTVEntry::LTVEntry(unsigned char id, unsigned char type, const char* str) {
	set_str(id,type,str);
}

LTVEntry::LTVEntry(unsigned char id, unsigned char type, unsigned long l) {
	set_num(id,type,l);
}


LTVEntry::~LTVEntry() {
	if (data_ != NULL and owner() ) {
		delete[] data_;
	}
	
	for (std::vector<LTVEntry*>::iterator i = contains().begin(); i != contains().end(); i++) {
		delete (*i);
	};
	
	contains().clear();
	data_ = NULL;
}

// unpack packet structure and return number of bytes really "red". The rest should stay in the buffer 
// as the beginning of not yet received rest of the new package

int LTVEntry::unpack(uint8_t* buffer, unsigned int buflen) {
	DEB_("LTVEntry::unpack:  --- process buffer %x[%u], buffer owner=%d",buffer,(long) buflen,owner());
	
	
	// to read at least the size of the package
	if (buflen < 4) {
		return -1;
	}
	DUMS_("stage1: can read length field");
	
	len_ = ltv_get_length(buffer);
	
	DUMS_("stage2: len detected: %d ", len_);
	DUMS_(hex_dump(buffer,4));
	DUMS_(hex_dump(buffer+4,4));
		
	//return underflow if we should expect more data
	if (buflen < len_) {
		DEB_("LTVEntry::unpack: buffer %x too short: %u, want to read %u bytes",buffer,buflen,len());
		return 0;
	}

	if (buflen >= len_) {
		
		id_ = ltv_get_id(buffer);
		type_ = ltv_get_type(buffer);
		
		DUM_("stage3: buffer of size %d could be fully read",len_);
		
		// if we are owning the buffer, fine, we will allocate.
		if ( owner () ) {
			DEB_("LTVEntry::unpack: Allocating: buffer[%u] for new package data", len_);
			
			// allocate memory for the whole content of the packet (there could be more data, but we are dealing now only with first package)
			data_ = new uint8_t[len_];
			
			// FIXME: above seems to be more correct than:
			//data = new uint8_t[buflen-__fsso_header_size()];
			
			
			DUM_(">> LTVEntry::unpack: orig.  buffer: %x       | len,type,id: %u,%u,%u",(long)buffer,(unsigned int)len_,(unsigned int)type_,(unsigned int)id_);		
			DUM_(">> LTVEntry::unpack: target buffer:       %x | len %uB",(unsigned long)data_,len_);
			DEB_(">> LTVEntry::unpack: copy   buffer: %x -> %x | len %uB",(unsigned long)buffer,(unsigned long)data_,len_);
			::memcpy(data_,buffer,len_);
			DUMS_("LTVEntry::unpack: memcpy: done");
		} else {
			
			// we are not owner of the buffer, so we can use pointer and create .
			DEB_("LTVEntry::unpack: Allocating: shadow buffer[%u] in %x",len_, buffer);
			data_ = buffer;
		}
		
		if (type_ == typ::cont) {
			// some stats
			unsigned int subentries=0;
		
			// start to dig all data inside
			unsigned int data_index = 0;
			unsigned int payload_len = len() -ltv_header_size();
			
			do {
				// all sub-entries should not allocate a single byte of memory => owner(false) will ensure this
				LTVEntry* l = new LTVEntry();
				l->owner(false);
				
				uint8_t* new_data = data() + data_index;
				
				unsigned int sub_red = l->unpack(new_data,payload_len);
				if (sub_red > 0) {
					contains().push_back(l);
					DEB_("LTVEntry::unpack:   sub-entry[%u] at %x[%u] | len %u",subentries,data(),(long)data_index,sub_red);
					
					data_index += sub_red;
					subentries++;
				} else {
					WAR_("LTVEntry::unpack:   sub-entry[%u] ERROR at %x[%u] | len %u",subentries,data(),(long)data_index,sub_red);
					delete l;
					break;
				}
				
				// this is correct place to finish the loop!
				if (data_index >= payload_len) {
					DEB_("LTVEntry::unpack: last sub-entry[%u] finished at %x[%u] | len %u",subentries,data(),(long)data_index,(long) payload_len);
					break;
				}
				
			} while (1);
		}
	}

	DEB_("LTVEntry::unpack: finished buffer @%x[%u]",buffer,(long) buflen);
	return len_;
}

std::string LTVEntry::hr(int ltrim) {
	
	int tr = 0;
	if (ltrim > 0) {
		tr = ltrim + 4;
	}

	std::string p = std::string();
	for (int i=0; i<tr; i++) { p += ' ';}
	
	std::string r;
	if (tr == 0) r += p + "LTVEntry::hr: packet human readable form:\n\n";
	r += p + "Package length : " + std::to_string((unsigned int)len_) +'\n';
	r += p + "Package id     : " + std::to_string((unsigned int)id_) + '\n' ;
	r += p + "Package type   : " + std::to_string((unsigned int)type_) + '\n';
	r += p + "Data (" + std::to_string((unsigned int)len_-ltv_header_size()) + "B):\n";
	
	if (type_ == typ::num || type_ == typ::ip) {
		in_addr dd_addr = *(in_addr*)data();
		uint32_t dd_int = ntohl(*(uint32_t*)data());
		const char *ip = ::inet_ntoa((in_addr)dd_addr);
		
		r += p + "Value (number) : " + std::to_string(dd_int) + " / " + ip + '\n' ;

	} else
	if (type_ == typ::str) {
		std::string s = std::string((char*)data(),(unsigned int)len_-ltv_header_size());
		r += p + "Value (string) : " + s + '\n' ;
	} else 
	if (type_ == typ::cont) {
		r += p + "... " + std::to_string(contains().size()) + " element(s):\n";
	} else
	{
		r += hex_dump(data(),datalen(),ltrim);
	};
	
	if (tr != 0) r+="\n";
	
	
	for (std::vector<LTVEntry*>::iterator i = contains().begin(); i != contains().end(); i++ ) {
		r+=(*i)->hr(tr+4);
	}
	
	return r;
}

std::string LTVEntry::data_str() {
	return std::string((char*)data(),(unsigned int)len_-ltv_header_size());
}

std::string LTVEntry::data_str_ip() {
	in_addr dd_addr = *(in_addr*)data();
	const char *ip = ::inet_ntoa((in_addr)dd_addr);
	return std::string(ip);
}


void LTVEntry::clear() {
	if (data_ != NULL && owner()) {
		free(data_);
	}
	len(0);
	id(0);
	type(0);
	
	owner(false);
}


void LTVEntry::set_str(unsigned char i, unsigned char t, const char* str) {
	
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
	
	clear();
	
	id_ = i;
	type_ = t;
	size_t data_len = size;
	size_t str_len = strlen(str);
	data_ = new uint8_t[data_len+ltv_header_size()];
	owner(true);
	memset(data(),0,size);
	memcpy(data(),str,str_len);
	
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
	
	*(uint32_t*)data() = htonl(d);
	
	len_ = ltv_header_size() + data_len;
	
	ltv_set_length(buffer(),len());
	ltv_set_type(buffer(),type());
	ltv_set_id(buffer(),id());	
}

void LTVEntry::set_ip(unsigned char id, unsigned char type, const char* str) {
	struct in_addr inp;
	inet_aton(str,&inp);
	
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
	 
	::buffer *b;
	
	// we need to know position where to store length of packed container!
	int length_pos = 0;
	bool this_is_owner = false;
	
	if (buf != NULL) { 
		b = buf; 
		length_pos = b->size();

	}
	else {
		b = new ::buffer();
		b->attach(data_,len_);
		b->size(len_);
		this_is_owner = true;
		//keep length_pos = 0; buffer is already filled with 6 bytes of container header
	}
	
	
	int sub_bytes = 0;
	if (type() == typ::cont) {

		if (! this_is_owner ) {
			//buffer owner already appended the buffer when initialized		
			b->append(buffer(),buflen());
		}
		
		for (std::vector<LTVEntry*>::iterator i = contains().begin(); i != contains().end(); i++ ) {
			sub_bytes += (*i)->pack(b);
		}

		len(len() + sub_bytes);
		ltv_set_length(b->data()+(length_pos),len());	
		
		if(this_is_owner) {
			data_ = b->data();
			b->detach();
			owner(true);
			delete b;
		}
		
		return len();
		
	} else {
		// this is not the container: return already allocated space
		if (buflen() > 0) {
			b->append(buffer(),buflen());
			DEB_("LTVEntry::pack: scalar %x packed in %d bytes",this,buflen());
			return buflen();
		} else {
			WAR_("LTVEntry::pack: warning - uninitialized LTVEntry at %x",this);
			return 0;
		} 
	}
}


LTVEntry* LTVEntry::search(const std::vector<int>& path) {
        
        DEBS_("LTVEntry::search:");
        
        LTVEntry* current = this;
        
        
        for (int t: path) {

                DEB_("LTVEntry::search: token %d",t);
                
                bool found = false;
                
                for(std::vector<LTVEntry*>::iterator j = current->contains().begin(); j != current->contains().end(); j++ ) {
                        if ((*j)->id() == t) {
                                current = (*j);
                                DEB_("LTVEntry::search: hit at %x",(*j));
                                found = true;
                                break;
                        }
                }
                
                if (! found) {
                        DEBS_("LTVEntry::search: failed");
                        return NULL;
                } 
        }
        
        DEB_("LTVEntry::search: found match at %x",current);    
        return current;
}