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
  void counter_alloc(size_type s);
  void counter_free(size_type s);

  virtual ~buffer ();

  explicit buffer (size_type size = 0);
  buffer (size_type size, size_type capacity);
  buffer (const void* data, size_type size);
  buffer (const void* data, size_type size, size_type capacity);
  buffer (void* data, size_type size, size_type capacity,
          bool assume_ownership);

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
  void assign (void* data, size_type size, size_type capacity,
               bool assume_ownership);

  void append (buffer*);
  void append (const buffer&);
  void append (const void* data, size_type size);

  template<typename T>
  void append (T const& r) { append(&r, sizeof(T)); };

  void fill (unsigned char value = 0);

  size_type size () const;
  bool size (size_type);
  size_type capacity () const;
  bool capacity (size_type);
  bool empty () const;
  void clear ();

  unsigned char* data ();
  const unsigned char* data () const;

  unsigned char& operator[] (size_type);
  unsigned char operator[] (size_type) const;
  unsigned char& at (size_type);
  unsigned char at (size_type) const;
  
  template <typename T> T get_at(unsigned int idx) const;
  template <typename T> static T get_at_ptr(unsigned char* data);

  size_type find (unsigned char, size_type pos = 0) const;
  size_type rfind (unsigned char, size_type pos = npos) const;

  //ast additions
  std::string str();
  
  void flush (size_type);
  buffer view(unsigned int, buffer::size_type);
  buffer view();
  
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


inline buffer::~buffer () {
    if (free_ && capacity_ > 0) {

        if(use_pool) {
            try {
                memPool::pool().release({data_, capacity_});
            }
            catch(mempool_bad_alloc const& e) {
                ; // there is nothing to do unfortunately
            }
        }
        else {
            delete[] data_;
            counter_free(capacity_);
        }
    }
}

inline buffer::buffer (size_type s)
    : free_ (true) {

    if (use_pool) {
        mem_chunk_t mch = memPool::pool().acquire(s);
        data_ = mch.ptr;
        capacity_ = mch.capacity;
    } else {
        data_ = (s != 0 ? new unsigned char[s] : nullptr);
        capacity_ = s;

        counter_alloc(s);
    }

   size_ = 0;
}

inline buffer::buffer (size_type s, size_type c)
    : free_ (true)
{
    if (s > c)
        throw std::invalid_argument ("size greater than capacity");

    if (use_pool) {
        mem_chunk_t mch = memPool::pool().acquire(c);
        data_ = mch.ptr;
        capacity_ = mch.capacity;
    }
    else {
        data_ = (c != 0 ? new unsigned char[c] : 0);
        capacity_ = c;
        counter_alloc(c);
    }
    size_ = s;
}

inline buffer::buffer (const void* d, size_type s)
    : free_ (true)
{
    if (s != 0) {

        if(use_pool) {
            mem_chunk_t mch = memPool::pool().acquire(s);
            data_ = mch.ptr;
            capacity_ = mch.capacity;
        }
        else {
            data_ = new unsigned char[s];
            capacity_ = s;
            counter_alloc(s);
        }

        // copy only originally requested amount of bytes
        std::memcpy (data_, d, s);
    }
    else {
        data_ = nullptr;
    }

    size_ = s;
}

inline buffer::buffer (const void* d, size_type s, size_type xc)
    : free_ (true)
{
    size_type c = xc;

  if (s > c)
    throw std::invalid_argument ("size greater than capacity");

  if (c != 0)
  {
      if(use_pool) {
          mem_chunk_t mch = memPool::pool().acquire(c);
          data_ = mch.ptr;
          c = mch.capacity;
      }
      else {
          data_ = new unsigned char[c];
          counter_alloc(c);
      }
    if (s != 0)
      std::memcpy (data_, d, s);
  }
  else
    data_ = nullptr;

  size_ = s;
  capacity_ = c;
}

inline buffer::buffer (void* d, size_type s, size_type c, bool own)
    : data_ (static_cast<unsigned char*> (d)), size_ (s), capacity_ (c), free_ (own)
{
  if (s > c)
    throw std::invalid_argument ("size greater than capacity");
  
  if(own && !use_pool)
      counter_alloc(c);
}

inline buffer::buffer (const buffer& x)
    : free_ (true)
{
  if (x.capacity_ != 0)
  {
    if(x.free_) {

        if(use_pool) {
            mem_chunk_t mch = memPool::pool().acquire(x.capacity_);
            data_ = mch.ptr;
            capacity_ = mch.capacity;
        }
        else {
            data_ = new unsigned char[x.capacity_];
            counter_alloc(x.capacity_);
        }

        if (x.size_ != 0)
        std::memcpy (data_, x.data_, x.size_);
        
    } else {
        data_ = x.data_;
    }
  }
  else
    data_ = nullptr;

  free_ = x.free_;
  size_ = x.size_;

  // pool can allocate (and set) bigger capacity than requested
  if(!use_pool)
    capacity_ = x.capacity_;
}


inline buffer& buffer::operator= (const buffer& x)
{
  if (&x != this)
  {
    if (x.size_ > capacity_ or not data_)
    {
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
  
      capacity_ = x.capacity_;
      
      if(x.free_) {

          if(use_pool) {
              mem_chunk_t mch = memPool::pool().acquire(x.capacity_);
              data_ = mch.ptr;
              capacity_  = mch.capacity;
          }
          else {
              data_ = new unsigned char[x.capacity_];
              counter_alloc(x.capacity_);
          }
        free_ = true; 
      } else {
        data_ = x.data_;
        free_ = false;
      }
    }

    if (x.size_ != 0 && x.free_) // copy only if original had ownership: honor ownership
      std::memcpy (data_, x.data_, x.size_);

    size_ = x.size_;
  }

  return *this;
}

inline void buffer::swap (buffer& x)
{
  unsigned char* d (x.data_);
  size_type s (x.size_);
  size_type c (x.capacity_);
  bool f (x.free_);

  x.data_ = data_;
  x.size_ = size_;
  x.capacity_ = capacity_;
  x.free_ = free_;

  data_ = d;
  size_ = s;
  capacity_ = c;
  free_ = f;
}

inline unsigned char* buffer::detach ()
{
  unsigned char* r (data_);

  data_ = nullptr;
  size_ = 0;
  capacity_ = 0;

  return r;
}

inline void buffer::assign (const void* d, size_type s)
{
  if (s > capacity_)
  {
    if (free_ && data_ != nullptr) {
        if(use_pool) {
            memPool::pool().release( { data_, capacity_ } );
        } else {
            delete[] data_;
            counter_free(capacity_);
        }
    }

    if(use_pool) {
        mem_chunk_t mch = memPool::pool().acquire(s);

        data_ = mch.ptr;
        capacity_ = mch.capacity;
    }
    else {
        data_ = new unsigned char[s];
        counter_alloc(s);
    }

    capacity_ = s;
    free_ = true;
  }

  if (s != 0 && d != nullptr)
    std::memcpy (data_, d, s);

  size_ = s;
}

inline void buffer::assign (void* d, size_type s, size_type c, bool own)
{
  if (free_ && data_ != nullptr) {

      if(use_pool) {
          memPool::pool().release( { data_, capacity_ } );
      }
      else {
          delete[] data_;
          counter_free(capacity_);
      }
  }

  data_ = static_cast<unsigned char*> (d);
  size_ = s;
  capacity_ = c;
  free_ = own;
  
  if(own && !use_pool)
      counter_alloc(c);
}

inline void buffer::attach(void* d, size_type s) {
    assign(d,s,s,true);
}


inline void buffer::append (buffer* b)
{
    append (b->data (), b->size ());
}


inline void buffer::append (const buffer& b)
{
  append (b.data (), b.size ());
}

inline void buffer::append (const void* d, size_type s)
{
  if (s != 0)
  {
    size_type ns (size_ + s);

    if (capacity_ < ns)
      capacity (ns);

    std::memcpy (data_ + size_, d, s);
    size_ = ns;
  }
}

inline void buffer::fill (unsigned char v)
{
  if (size_ > 0)
    std::memset (data_, v, size_);
}

inline buffer::size_type buffer::size () const
{
  return size_;
}

inline bool buffer::size(size_type s)
{
    bool r = false;

    if (capacity_ < s) {
        // resize buffer
        r = capacity (s);
    }

    size_ = s;
    return r;
}

inline buffer::size_type buffer::capacity () const
{
  return capacity_;
}

inline bool buffer::capacity (size_type c)
{
  // Ignore capacity decrease requests.
  //
  if (capacity_ >= c)
    return false;

  unsigned char* d = nullptr;
  size_type cd = 0;

  if(use_pool) {

      mem_chunk_t mch = memPool::pool().acquire(c);
      d = mch.ptr;
      cd = mch.capacity;
  }
  else {
      d = (new unsigned char[c]);

      if (d == nullptr) {
          return false;
      } else {
          counter_alloc(c);
      }
  }

  if (size_ != 0)
    std::memcpy (d, data_, size_);

  if (free_ && data_ != nullptr)  {
      if(use_pool) {
          memPool::pool().release( { data_, capacity_ } );
      }
      else {
          delete[] data_;
          counter_free(capacity_);
      }
  }

  data_ = d;

    // pool can allocate and set more bytes than requested
    if(!use_pool) {
        capacity_ = c;
    }else {
        capacity_ = cd;
    }
    free_ = true;

  return true;
}

inline bool buffer::empty () const
{
  return size_ == 0;
}

inline void buffer::clear ()
{
  size_ = 0;
}

inline unsigned char* buffer::data ()
{
  return data_;
}

inline const unsigned char* buffer::data () const
{
  return data_;
}

inline unsigned char& buffer::operator[] (size_type i)
{
  return data_[i];
}

inline unsigned char buffer::operator[] (size_type i) const
{
  return data_[i];
}

inline unsigned char& buffer::at (size_type i)
{
  if (i >= size_)
    throw std::out_of_range ("buffer: index out of range: " + std::to_string((int)i) + " of " + std::to_string(size_));

  return data_[i];
}

inline unsigned char buffer::at (size_type i) const
{
  if (i >= size_)
    throw std::out_of_range ("buffer: index out of range: " + std::to_string((int)i) + " of " + std::to_string(size_));

  return data_[i];
}

template <typename T>
T buffer::get_at(unsigned int idx) const
{
    if(idx + sizeof(T) - 1 >= size_)
        throw std::out_of_range ("buffer: index out of range: " + std::to_string((int)idx) + " of " + std::to_string(size_));
    
    return *((T*)(&data_[idx]));
}


template <typename T> T buffer::get_at_ptr(unsigned char* data) {
    return *((T*)(data));
}

inline buffer::size_type buffer::find (unsigned char v, size_type pos) const
{
  if (size_ == 0 || pos >= size_)
    return npos;

  unsigned char* p (static_cast<unsigned char*> (std::memchr (data_ + pos, v, size_ - pos)));
  return p != 0 ? static_cast<size_type> (p - data_) : npos;
}

inline buffer::size_type buffer::rfind (unsigned char v, size_type pos) const
{
  // memrchr() is not standard.
  //
  if (size_ != 0)
  {
    size_type n (size_);

    if (--n > pos)
      n = pos;

    for (++n; n-- != 0; )
      if (data_[n] == v)
        return n;
  }

  return npos;
}

inline bool operator== (const buffer& a, const buffer& b)
{
  return a.size () == b.size () &&
    std::memcmp (a.data (), b.data (), a.size ()) == 0;
}

inline bool operator!= (const buffer& a, const buffer& b)
{
  return !(a == b);
}


// AST
inline void buffer::flush(buffer::size_type b) {
    buffer::size_type bytes = b;
    
    if (bytes == 0 || bytes >= size_) {
        clear();
        return;
    }

    if (bytes < size_) {
        if( 2*bytes < size_) {
        std::memmove(data_,data_+bytes,size_-bytes);
        } else {
        std::memcpy(data_,data_+bytes,size_-bytes);
        }

        size_-=bytes;
    } else {
        throw std::out_of_range ("index out of range: too many bytes to flush: " + std::to_string((int)b) + " of " + std::to_string(size_) + "\n" + bt());
    }

}

inline buffer buffer::view(unsigned int pos, buffer::size_type len) {
    if (pos < size_) {
        // starting pos in the buffer
        
        if( pos+len <= size_) {
            // view inside buffer
            return buffer(data_ +pos, len, len, false);
        } else {
            // end of view outside buffer
            return buffer(data_ +pos, size_ - pos, size_ - pos, false);
        }
    }
    else {
        // start out of buffer margins!


        // return buffer();
        throw std::out_of_range("view out of bounds");
    }
}

inline buffer buffer::view() {
    return view(0,size());
}


inline std::string buffer::str() {
    return std::string((const char*)data(),size());
}

std::string regex_replace_fill(std::string str_sample, std::string str_match, std::string str_replacement, const char* str_fill_pattern=" ");

#endif