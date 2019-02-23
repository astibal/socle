/*
    Smithproxy- transparent proxy with SSL inspection capabilities.
    Copyright (c) 2014, Ales Stibal <astib@mag0.net>, All rights reserved.

    Smithproxy is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Smithproxy is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Smithproxy.  If not, see <http://www.gnu.org/licenses/>.
    
*/  

#ifndef SHMTABLE_HPP
  #define SHMTABLE_HPP


#include <cstring>
#include <vector>
#include <unordered_map>

#include <shmbuffer.hpp>

struct shared_table_header {
    unsigned int version;
    unsigned int entries;
    unsigned int row_size;
};

template<class RowType>
class shared_table : public shared_buffer {

public:  
  shared_table() {
      header_size = sizeof(struct shared_table_header);
      row_size = sizeof(RowType);
      memset(&cur_data_header,0,sizeof(struct shared_table_header));
      cur_data_header.row_size = sizeof(RowType);
  };
  virtual ~shared_table() {}
  
  int read_header() {
      shared_table_header* bh = (shared_table_header*)data();
      cur_data_header = *bh;
      
      if(sizeof(RowType) != (long unsigned int)header_rowsize()) {
	  return -1;
      }       
      
      return bh->version;
  }
  unsigned int header_version() { return cur_data_header.version; }
  unsigned int header_entries() { return cur_data_header.entries; }
  unsigned int header_rowsize() { return cur_data_header.row_size; }
  void reset_seen_version() { seen_version_ = 0; }
  unsigned int seen_version()   { return seen_version_; }
  void seen_version(unsigned int i)   { seen_version_ = i; }
  
  std::vector<RowType>& entries() { return entries_; }

    virtual int load() {

        read_header();

        if(seen_version() < header_version() || ( header_version() == 0 && seen_version() > 0)) {

            if (on_new_version(seen_version(),header_version())) {
                entries().clear();
            }
            seen_version(header_version());


//             printf("new table version available: %d\n",header_version());
//             printf("\"successfully authenticated users\" table:\n");
//             printf("my row_size is %d\n",(int)sizeof(struct logon_info));
//             printf("version %d: entries %d row_size: %d\n",header_version(), header_entries(),header_rowsize());

            unsigned char* records = &data()[sizeof(struct shared_table_header)];
            for (unsigned int n = 0 ; n < header_entries() ; n++) {
                RowType rec;
                int sz = rec.load(records);
                //printf("%s: %16s \t groups: %s\n",inet_ntoa(*(in_addr*)rec->ip),rec->username,rec->groups);

                if(on_new_entry(&rec)) {
                    entries().push_back(rec);
                }

                records+=sz;
            }

            on_new_finished();
            return entries().size();
        } else {
//             printf("same version %d:%d\n",seen_version_,header_version());
        }

        return -1;
    }
  
  unsigned int write_header(bool increase_version=false, int n_entries=-1) {
      
      if(increase_version) {
          seen_version(seen_version()+1);
          cur_data_header.version++;
      }
      cur_data_header.entries = entries().size();

      if(n_entries >= 0) {
          cur_data_header.entries = n_entries;
      }
      cur_data_header.row_size = RowType::record_size();
      memcpy(data(),&cur_data_header,sizeof(struct shared_table_header));
     
      return sizeof(shared_table_header);
  }
  
  virtual int save(bool increase_version=false) {

      int n_written = 0;
      unsigned char* curpos = data() + sizeof(struct shared_table_header);
      for(typename std::vector<RowType>::iterator i = entries().begin(); i != entries().end() ; ++i) {
          RowType& r = (*i);
          unsigned int s = on_write_entry(curpos,r);
          
          if(s > 0) {
                curpos += s;
                n_written++;
          }
      }  
      
      // we are writing header as the last, since we don't know how many entries we really wrote
      write_header(increase_version,n_written);
      
      return curpos - data();
  };

  virtual unsigned int on_write_entry(unsigned char* ptr, RowType& r) {
      memcpy(ptr,r.data()->data(),r.data()->size());
      return r.data()->size();
  }
  
  // reuturn true if table should be cleared (yes!)
  virtual bool on_new_version(int o, int n) { return true; }
  virtual bool on_new_entry(RowType* r) { return true; }
  virtual void on_new_finished() {}
  
  
protected:
    unsigned int version = 0;
    unsigned int header_size = 0;
    unsigned int row_size = 0;

    std::vector<RowType> entries_;
    unsigned int seen_version_ = 0;
    
private:
    shared_table_header cur_data_header;
};







template<class KeyType,class RowType>
class shared_map : public shared_table<RowType> {

public:
    shared_map() : shared_table<RowType>() {
    };
    virtual ~shared_map() {}

    virtual bool on_new_version(int o, int n) {
        map_entries().clear();
        return shared_table<RowType>::on_new_version(o,n);
    }
    virtual bool on_new_entry(RowType* r) {
        map_entries()[get_row_key(r)] = *r;
        return true;
    }
    virtual unsigned int on_write_entry(unsigned char* ptr, RowType& r) {
        
        KeyType row_key = get_row_key(&r);
        auto iter = map_entries().find(row_key);

        if(iter != map_entries().end()) {
            // we would the currently written entry in key map. OK.
            return shared_table<RowType>::on_write_entry(ptr,r);
        } else {
            // this original entry is not in keys.. deleted/filtered on load.
            // don't write it!
            return 0;
        }
    }

    virtual KeyType get_row_key(RowType* r) = 0;


    std::unordered_map<KeyType,RowType>& map_entries() { return map_entries_; };
protected:
    std::unordered_map<KeyType,RowType> map_entries_;
};


#endif
