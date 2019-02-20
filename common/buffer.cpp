#include <buffer.hpp>

unsigned long long buffer::alloc_bytes = 0;
unsigned long long buffer::alloc_count = 0;
unsigned long long buffer::free_bytes = 0;
unsigned long long buffer::free_count = 0;

memPool buffer::pool(5000,1000,10000,1000,800);
bool    buffer::use_pool = false;

unsigned long long memPool::stat_acq = 0;
unsigned long long memPool::stat_acq_size = 0;

unsigned long long memPool::stat_ret = 0;
unsigned long long memPool::stat_ret_size = 0;

unsigned long long memPool::stat_alloc = 0;
unsigned long long memPool::stat_alloc_size = 0;

unsigned long long memPool::stat_free = 0;
unsigned long long memPool::stat_free_size = 0;

#ifdef SOCLE_MEM_PROFILE  
std::unordered_map<std::string,int> buffer::alloc_map;
std::mutex buffer::alloc_map_lock_;
#endif

// regex_replace example
#include <iostream>
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
// On the contrary, it also seems that less bytes received than advertised is considered as transfer error.

std::string regex_replace_fill(std::string str_sample, std::string str_match, std::string str_replacement, const char* str_fill_pattern) {
    
  std::string sample(str_sample);
  std::regex match (str_match);
  std::string replacement  = str_replacement;
  std::string fill_pattern (str_fill_pattern);

  // using string/c-string (3) version:
  std::string result =  std::regex_replace (sample,match,replacement);

  int dif = sample.size() - result.size();
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
      result = "";
      
      // do replacements one by one. On last one stop and perform the fill operation!
      for (int i = 0; std::regex_search (s,m,match) ; i++) {

        // we are interested only in [0] - it's whole match!
        result += m.prefix().str() + std::regex_replace(m[0].str(),match,replacement);

        //last occurence, fill with the pattern!
        if(i == match_count - 1) {
            //std::cout << "last" << std::endl;
            
            std::string appendix = m.suffix().str();
            
            //for the case test sizes and diff again
            dif = sample.size() - result.size();
            if(dif > 0) {
                // we are shorter with result, which may break things. Try to fill, but count also with
                // bytes after the last match
                for(unsigned int r = 0; r < dif - appendix.size() ; r+=fill_pattern.size()) {
                    result += fill_pattern;
                }
            }

            // add the rest of the string
            result += appendix;
        } 


        s = m.suffix().str();
      }
  }

 
  return result;
}