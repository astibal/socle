#ifndef BUFFER_HPP_INCLUDED
#define BUFFER_HPP_INCLUDED

//
//  buffer.hpp
//
//  Copyright (c) 2011 Boris Kolpackov, (c) 2014 Ales Stibal
//
//  Distributed under the Boost Software License, Version 1.0. (See
//  accompanying file LICENSE_1_0.txt or copy at
//  http://www.boost.org/LICENSE_1_0.txt)
//
//  Simple memory buffer abstraction. Version 1.0.0.
//

#include <cstddef>   // std::size_t
#include <cstring>   // std::memcpy, std::memcmp, std::memset, std::memchr
#include <stdexcept> // std::out_of_range, std::invalid_argument
#include <string>
#include <vector>
#include <mutex>

#include <socle_common.hpp>
#include <display.hpp>
#include <mempool/mempool.hpp>

#ifdef SOCLE_MEM_PROFILE
#include <unordered_map>
#include <mutex>
#endif

#include <log/logan.hpp>
#include <ostream>

class buffer
{
public:
  typedef std::size_t size_type;

  static const size_type npos = static_cast<size_type> (-1);

  static unsigned long long alloc_bytes;
  static unsigned long long alloc_count;
  static unsigned long long free_bytes;
  static unsigned long long free_count;

  static bool use_pool;


#ifdef SOCLE_MEM_PROFILE  
  static std::unordered_map<std::string,int> alloc_map;
  static std::mutex alloc_map_lock_;
  std::string my_bt;
  void counter_alloc_bt();
  void counter_free_bt();
  static void counter_clear_bt();
  static inline void alloc_map_lock() { alloc_map_lock_.lock(); };
  static inline void alloc_map_unlock() { alloc_map_lock_.unlock(); };
#endif
  static void counter_alloc(size_type s);
  static void counter_free(size_type s);

  virtual ~buffer ();

  explicit buffer (size_type size = 0);
  buffer (size_type size, size_type capacity);
  buffer (const void* data, size_type size);
  buffer (const void* data, size_type size, size_type capacity);
  buffer (void* data, size_type size, size_type capacity, bool own);

  buffer (const buffer&);
  buffer& operator= (const buffer&);


  buffer(buffer&& ref) noexcept : data_(nullptr), size_(0), capacity_(0), free_(true) {

      if(&ref != this) {
          data_ = ref.data_;
          capacity_ = ref.capacity_;
          size_ = ref.size_;

          free_ = ref.free_;

          // auto log = logan::create("buffer");
          // _deb("buffer owner move trace ctor(buffer&&):\n %s", bt(true).c_str());

          ref.free_ = false; // make the almost-invalid reference not free our memory
      }
  }

  buffer& operator= (buffer&& ref) noexcept {

      if (free_ and data_ != nullptr ) {
          if(use_pool) {

              try {
                  memPool::pool().release( { data_, capacity_} );
              }
              catch(mempool_bad_alloc const& e) {
                  ; // there is nothing to do unfortunately
              }
          }
          else {
              delete[] data_;  // we HAD ownership
              counter_free(capacity_);
          }
      }

      // auto log = logan::create("buffer");
      // _deb("buffer owner move trace op=(buffer&&):\n %s", bt(true).c_str());

      data_ = ref.data_;
      capacity_ = ref.capacity_;
      size_ = ref.size_;

      free_ = ref.free_;

      ref.free_ = false; // make the almost-invalid reference not free our memory

      return *this;
  };
  
  void swap (buffer&);
  unsigned char* detach ();

  void assign (const void* data, size_type size); // copy
  void attach (void* data, size_type size); // take ownership
  void assign (void* data, size_type size, size_type capacity, bool own);

  void append (buffer*);
  void append (const buffer&);
  void append (const void* data, size_type size);

  template<typename T>
  void append (T const& r) { append(&r, sizeof(T)); };

  void fill (unsigned char value = 0);

  [[nodiscard]] size_type size () const;
  [[nodiscard]] bool empty () const;
  [[nodiscard]] size_type capacity () const;

  bool size (size_type);
  bool capacity (size_type);
  void clear ();

  unsigned char* data ();
  [[nodiscard]] const unsigned char* data () const;

  unsigned char& operator[] (size_type);
  unsigned char operator[] (size_type) const;
  unsigned char& at (size_type);
  [[nodiscard]] unsigned char at (size_type) const;
  
  template <typename T> T get_at(unsigned int idx) const;
  template <typename T> static T get_at_ptr(unsigned char const* data);

  [[nodiscard]] size_type find (unsigned char, size_type pos = 0) const;
  [[nodiscard]] size_type rfind (unsigned char, size_type pos = npos) const;

  //ast additions
  std::string str();
  
  void flush (size_type);
  buffer view(unsigned int, buffer::size_type);
  buffer view();

  friend std::ostream& operator<<(std::ostream& os, buffer const& b);
  
private:
  unsigned char* data_ = nullptr;
  size_type size_ = 0;
  size_type capacity_ = 0;
  bool free_ = true;
};

bool operator== (const buffer&, const buffer&);
bool operator!= (const buffer&, const buffer&);


//
// Implementation.
//

inline void buffer::counter_alloc(size_type s) {
    if(s > 0) {
        alloc_bytes += s;
        alloc_count++;
#ifdef SOCLE_MEM_PROFILE
        counter_alloc_bt();
#endif
    }    
}

inline void buffer::counter_free(size_type s) {
    if(s > 0) {
        free_bytes += s;
        free_count++;
#ifdef SOCLE_MEM_PROFILE
        counter_free_bt();
#endif
    }    
}

#ifdef SOCLE_MEM_PROFILE  
inline void buffer::counter_alloc_bt() {
    if(my_bt.size() > 0) {
        counter_free_bt();
    }
    my_bt = bt();
    
    std::lock_guard<std::mutex> l(alloc_map_lock_);
    auto it = alloc_map.find(my_bt);
    if(it == alloc_map.end()) {
        alloc_map[my_bt] = 0;
    }
    alloc_map[my_bt]++;
}
inline void buffer::counter_free_bt() {
    std::lock_guard<std::mutex> l(alloc_map_lock_);
    auto it = alloc_map.find(my_bt);
    
    if(it == alloc_map.end()) {
        alloc_map[my_bt] = 0;
    } else {
        alloc_map[my_bt]--;
    }
}
inline void buffer::counter_clear_bt() {
    std::lock_guard<std::mutex> l(alloc_map_lock_);
    alloc_map.clear();
}

#endif


template <typename T>
inline T buffer::get_at(unsigned int idx) const
{
    if(idx + sizeof(T) - 1 >= size_)
        throw std::out_of_range ("buffer: index out of range: " + std::to_string((int)idx) + " of " + std::to_string(size_));

    return *((T*)(&data_[idx]));
}

template <typename T>
inline T buffer::get_at_ptr(unsigned char const* data) {
    return *((T*)(data));
}


std::string regex_replace_fill(std::string const& str_sample, std::string const& str_match, std::string const& str_replacement, const char* str_fill_pattern= " ");

#endif