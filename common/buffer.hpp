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
  using size_type =  std::size_t;

  static constexpr const size_type npos = static_cast<size_type> (-1);

  static inline unsigned long long alloc_bytes = 0LL;
  static inline unsigned long long alloc_count = 0LL;
  static inline unsigned long long free_bytes = 0LL;
  static inline unsigned long long free_count = 0LL;

  static inline bool use_pool = true;


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

  void dealloc() noexcept;
  void release() noexcept;
  virtual ~buffer ();

  explicit buffer (size_type size = 0);
  buffer (size_type size, size_type capacity);
  buffer (const void* data, size_type size);
  buffer (const void* data, size_type size, size_type capacity);
  buffer (void* data, size_type size, size_type capacity, bool own);

  buffer (const buffer&);
  buffer& operator= (const buffer&);


  buffer(buffer&& ref) noexcept {

      if(&ref != this) {
          data_ = ref.data_;
          capacity_ = ref.capacity_;
          size_ = ref.size_;

          free_ = ref.free_;

          ref.free_ = false; // make the almost-invalid reference not free our memory
      }
  }

  buffer& operator= (buffer&& ref) noexcept {

      if (free_ and data_ != nullptr ) {
          if(use_pool) {

              memPool::pool().release( { data_, capacity_} );
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
  
  void swap (buffer&) noexcept;
  unsigned char* detach ();

  void assign (const void* data, size_type size); // copy
  void assign (std::string_view data); // copy
  void assign (void* data, size_type size, size_type capacity, bool own);
  void attach (void* data, size_type size); // take ownership

  void append (const buffer*);
  void append (const buffer&);
  void append (const void* data, size_type size);

  template<typename T,
          typename = std::enable_if_t<std::negation_v<std::is_pointer<T>>>,
          typename = std::enable_if_t<std::negation_v<std::is_base_of<buffer,std::remove_reference<T>>>>,
          typename = std::enable_if_t<std::is_trivially_copyable_v<std::remove_reference<T>>>
          >
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
  template <typename T> void set_at(unsigned int idx, T val);
  template <typename T> static T get_at_ptr(uint8_t const* data);

  template <std::size_t SZ>
  std::array<uint8_t, SZ> copy_from(std::size_t start) const {
      if(start + SZ > size()) throw std::out_of_range("out of range");

      std::array<uint8_t, SZ> ret;
      std::memcpy(ret.data(), data() + start, SZ);
      return ret;
  }

  [[nodiscard]] size_type find (unsigned char, size_type pos = 0) const;
  [[maybe_unused]] [[nodiscard]] size_type rfind (unsigned char, size_type pos = npos) const;

  //ast additions
  [[nodiscard]] std::string str() const;
  [[nodiscard]] std::string_view string_view() const;
  
  void flush (size_type);
  buffer view(size_type pos, buffer::size_type len) const;
  buffer view() const;
  buffer view(size_type pos) const { return view(pos, size() - pos); };

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
    if(idx + sizeof(T) > size_)
        throw std::out_of_range ("buffer: index out of range: " + std::to_string((int)idx) + " of " + std::to_string(size_));

    return *((T*)(&data_[idx]));
}

template <typename T>
inline void buffer::set_at(unsigned int idx, T val)
{
    if(idx + sizeof(T) > size_)
        throw std::out_of_range ("buffer: index out of range: " + std::to_string((int)idx) + " of " + std::to_string(size_));

    *((T*)(&data()[idx])) = val;
}

template <typename T>
inline T buffer::get_at_ptr(uint8_t const* data) {
    return *((T*)(data));
}


std::optional<std::string> regex_replace_fill(std::string const& str_sample, std::string const& str_match, std::string const& str_replacement, const char* str_fill_pattern);

#endif