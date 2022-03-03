#include <buffer.hpp>


#ifdef SOCLE_MEM_PROFILE  
std::unordered_map<std::string,int> buffer::alloc_map;
std::mutex buffer::alloc_map_lock_;
#endif

#include <string>
#include <regex>
#include <iterator>

// replace strings on regex basis BUT don't allow the resulting string be shorter than original. 
// This is important in some scenarios when you are replacing inline data, which are already indicated to be of some specific size.
// Good example is Content-Length, or Transfer-Encoding: chunked, which indicate data size.

// in proxying scenarios, unless you buffer whole message, you can't know this value, and if you do, you can't 
// change it, based on replace result.
// For this purpose this function exists. It replaces all occurrences using std::regex_replace. But if the result is shorter,
// yet another attempt is performed, one by one occurrence replacement.
// If the last replacement is performed (and content is shorter), last replacement string is suffixed with str_fill_pattern to match original 
// size.
// If pattern contains more than one character, resulting buffer could be larger. 
// 
// Note on http chunked encoding: 
// it seems that it's tolerated when client receives more bytes in the chunk than advertised.
// On the contrary, it also seems that fewer bytes received than advertised is considered as transfer error.


void buffer::release() noexcept {
    if (free_ && capacity_ > 0) {

        if(use_pool) {
            memPool::pool().release({data_, capacity_});
        }
        else {
            delete[] data_;
            counter_free(capacity_);
        }
    }

    capacity_ = 0L;
    size_ = 0L;
    data_ = nullptr;
    free_ = false;
}

buffer::~buffer () {
    release();
}

buffer::buffer (size_type s) {

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

buffer::buffer (size_type s, size_type c) {

    if (s > c)
        throw std::invalid_argument("size greater than capacity");

    if (use_pool) {
        mem_chunk_t mch = memPool::pool().acquire(c);
        data_ = mch.ptr;
        capacity_ = mch.capacity;
    }
    else {
        data_ = (c != 0 ? new unsigned char[c] : nullptr);
        capacity_ = c;
        counter_alloc(c);
    }
    size_ = s;
}

buffer::buffer (const void* d, size_type s) {

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

buffer::buffer (const void* d, size_type size, size_type capacity) {

    size_type c = capacity;

    if (size > c)
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
        if (size != 0)
            std::memcpy (data_, d, size);
    }
    else
        data_ = nullptr;

    size_ = size;
    capacity_ = c;
}

buffer::buffer (void* d, size_type size, size_type capacity, bool own)
        : data_ (static_cast<unsigned char*> (d)), size_ (size), capacity_ (capacity), free_ (own)
{
    if (size > capacity)
        throw std::invalid_argument ("size greater than capacity");

    if(own && !use_pool)
        counter_alloc(capacity);
}

buffer::buffer (const buffer& x) {

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


buffer& buffer::operator=(const buffer& x)
{
    if(&x == this) return *this;

    if (x.size_ > capacity_ or not data_)
    {
        if (free_ and data_ != nullptr ) {
            if(use_pool) {

                memPool::pool().release( { data_, capacity_} );
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

    return *this;
}

void buffer::swap (buffer& x) noexcept
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

unsigned char* buffer::detach()
{
    unsigned char* r (data_);

    data_ = nullptr;
    size_ = 0;
    capacity_ = 0;

    return r;
}

void buffer::assign (const void* d, size_type s)
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

void buffer::assign (void* d, size_type s, size_type c, bool own)
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

void buffer::attach(void* d, size_type s) {
    assign(d,s,s,true);
}


void buffer::append (buffer* b)
{
    append (b->data (), b->size ());
}


void buffer::append (const buffer& b)
{
    append (b.data (), b.size ());
}

void buffer::append (const void* d, size_type s)
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

void buffer::fill (unsigned char v)
{
    if (size_ > 0)
        std::memset (data_, v, size_);
}

buffer::size_type buffer::size () const
{
    return size_;
}

bool buffer::size(size_type s)
{
    bool r = false;

    if (capacity_ < s) {
        // resize buffer
        r = capacity (s);
    }

    size_ = s;
    return r;
}

buffer::size_type buffer::capacity () const
{
    return capacity_;
}

bool buffer::capacity (size_type c)
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

bool buffer::empty () const
{
    return size_ == 0;
}

void buffer::clear ()
{
    size_ = 0;
}

unsigned char* buffer::data ()
{
    return data_;
}

const unsigned char* buffer::data () const
{
    return data_;
}

unsigned char& buffer::operator[] (size_type i)
{
    return data_[i];
}

unsigned char buffer::operator[] (size_type i) const
{
    return data_[i];
}

unsigned char& buffer::at (size_type i)
{
    if (i >= size_)
        throw std::out_of_range ("buffer: index out of range: " + std::to_string((int)i) + " of " + std::to_string(size_));

    return data_[i];
}

unsigned char buffer::at (size_type i) const
{
    if (i >= size_)
        throw std::out_of_range ("buffer: index out of range: " + std::to_string((int)i) + " of " + std::to_string(size_));

    return data_[i];
}


buffer::size_type buffer::find (unsigned char v, size_type pos) const
{
    if (size_ == 0 || pos >= size_)
        return npos;

    auto* position (static_cast<unsigned char*> (std::memchr (data_ + pos, v, size_ - pos)));
    return position ? static_cast<size_type> (position - data_) : npos;
}

buffer::size_type buffer::rfind (unsigned char v, size_type pos) const
{
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

bool operator== (const buffer& a, const buffer& b)
{
    return a.size () == b.size () &&
           std::memcmp (a.data (), b.data (), a.size ()) == 0;
}

bool operator!= (const buffer& a, const buffer& b)
{
    return !(a == b);
}


void buffer::flush(buffer::size_type b) {
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

buffer buffer::view(size_type pos, buffer::size_type len) {
    if (pos < size_) {
        // starting pos in the buffer

        if( pos+len <= size_) {
            // view inside buffer
            return {data_ +pos, len, len, false};
        } else {
            // end of view outside buffer
            return {data_ +pos, size_ - pos, size_ - pos, false};
        }
    }
    else {
        // start out of buffer margins!


        // return buffer();
        throw std::out_of_range("view out of bounds");
    }
}

buffer buffer::view() {
    return view(0,size());
}


std::string buffer::str() const {
    return std::string((const char*)data(),size());
}

std::string_view buffer::string_view() const {
    return { (const char*) data(), size() };
}



std::string regex_replace_fill(std::string const& sample, std::string const& str_match, std::string const& replacement, const char* str_fill_pattern) {
    

  std::regex match (str_match);
  std::string fill_pattern (str_fill_pattern);

  // using string/c-string (3) version:
  std::string result =  std::regex_replace (sample, match, replacement);

  auto dif = sample.size() - result.size();
  if(dif > 0) {
      // switching to fill mode
      
      std::smatch m;
      std::string s = sample;
      int match_count = 0;

      while (std::regex_search (s,m,match)) {
        match_count++;
        s = m.suffix().str();
      }

      s = sample;
      result.clear();

      std::stringstream result_add;
      
      // do replacements one by one. On last one stop and perform the fill operation!
      for (int i = 0; std::regex_search (s,m,match) ; i++) {

        // we are interested only in [0] - it's whole match!
        result_add << m.prefix().str() << std::regex_replace(m[0].str(), match, replacement);

        //last occurrence, fill with the pattern!
        if(i == match_count - 1) {

            std::string appendix = m.suffix().str();
            
            //for the case test sizes and diff again
            dif = sample.size() - result.size();
            if(dif > 0) {
                // we are shorter with result, which may break things. Try to fill, but count also with
                // bytes after the last match
                for(unsigned int r = 0; r < dif - appendix.size() ; r+=fill_pattern.size()) {
                    result_add << fill_pattern;
                }
            }

            // add the rest of the string
            result_add << appendix;
        } 

        s = m.suffix().str();
      }

      result = result_add.str();
  }

 
  return result;
}

std::ostream& operator<<(std::ostream& os, buffer const& b) {
    if(b.data_ and b.size_ > 0)
        return os.write(reinterpret_cast<const char*>(b.data()), b.size());

    return os;
}
