#include <buffer.hpp>

long long buffer::alloc_bytes = 0;
long long buffer::alloc_count = 0;
long long buffer::free_bytes = 0;
long long buffer::free_count = 0;

#ifdef SOCLE_MEM_PROFILE  
std::unordered_map<std::string,int> buffer::alloc_map;
std::mutex buffer::alloc_map_lock_;
#endif

