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

#ifndef SHMBUFFER_HPP
  #define SHMBUFFER_HPP

#include <semaphore.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>


// logger.hpp -- this file defines WAR_ and other logging macros.
// if you want to use this file alone, just replace WAR_ (and possibly others) with printf-like function
// of your choice.
#include <log/logan.hpp>

#include <string>

class shared_buffer {
protected:
    sem_t* semaphore = nullptr;
    std::string semaphore_name;
    std::string memory_name;
    int         memory_size;
    int         memory_fd;
    
    unsigned char* data_;
    unsigned int size_;
    unsigned int capacity_;
    
    bool        attached_ = false;

    static logan_lite& get_log() {
        static logan_lite l("internal.shm");
        return l;
    }
    
public:
    shared_buffer(): memory_size(0), memory_fd(-1), data_(nullptr), size_(0), capacity_(0) {}

    unsigned char* data()    { return data_; }
    [[nodiscard]] unsigned int   size()  const noexcept { return size_; }
    [[nodiscard]] unsigned int   capacity() const noexcept { return capacity_; }

    [[nodiscard]] bool attached() const noexcept { return attached_; }
    
    bool attach(const char* mem_name, const int mem_size, const char* sem_name, bool create_on_error=true) {

        auto log = get_log();

        if(attached()) {
            return true;
        }
        
        semaphore_name = sem_name;
        memory_name = mem_name;
        memory_size = mem_size;
        
        unsigned char* shared_memory = nullptr;
        memory_fd  = -1;

        bool will_initialize = false;
        
        semaphore = sem_open(semaphore_name.c_str(),O_RDWR,0600);
        if(semaphore == nullptr) {
            _war("Getting a handle to the semaphore failed; errno is %d", errno);
            if(create_on_error) {
                semaphore = sem_open(semaphore_name.c_str(),O_CREAT | O_RDWR,0600);
                if(semaphore == nullptr) {
                    _war("Failed to create semaphore as a fallback; errno is %d", errno);
                    goto fail;
                }
            } else {
                goto fail;
            }
        }
        
        memory_fd = shm_open(memory_name.c_str(), O_RDWR, 0600);
        if(memory_fd  == -1) {
            _war("Couldn't get a handle to the shared memory; errno is %d", errno);
            if(create_on_error) {
                memory_fd = shm_open(memory_name.c_str(), O_CREAT | O_RDWR, 0600);
                if(memory_fd == -1) {
                    _war("Failed to create new memory object; errno is %d", errno);
                    goto fail;
                }

                _dia("shared mem buffer file %s created", memory_name.c_str());

                if(ftruncate(memory_fd, memory_size) != 0) {
                    _dia("shared mem buffer file %s cannot be truncated: %s", memory_name.c_str(), string_error().c_str());
                    goto fail;
                }
                will_initialize = true;

            } else {
                goto fail;
            }
        } else {
            // we opened to be mapped file, check its size

            struct stat st{0};

            if(stat(memory_name.c_str(), &st) != 0) {
                _dia("shared mem buffer file %s cannot stat: %s", memory_name.c_str(), string_error().c_str());
            }
            else {
                if (st.st_size == 0) {
                    _dia("shared mem buffer file %s empty - resizing", memory_name.c_str());
                    if (ftruncate(memory_fd, memory_size) != 0) {
                        _dia("shared mem buffer file %s cannot be truncated: %s", memory_name.c_str(),
                             string_error().c_str());
                        goto fail;
                    }
                }
            }
        }

        shared_memory = (unsigned char*)mmap(nullptr, memory_size, PROT_READ | PROT_WRITE, MAP_SHARED, memory_fd, 0);

        if (shared_memory == MAP_FAILED) {
            _war("MMapping the shared memory failed; errno is %d", errno);
            goto fail;
        }
        

        if(will_initialize) {
            _dia("shared mem buffer file %s zeroized", memory_name.c_str());
            ::memset(shared_memory, 0, mem_size);
        }

        data_ = shared_memory;
        capacity_ = mem_size;
        size_ = capacity_;

        // don't go back here
        attached_ = true;
        
        return true;
        

        fail:
        return false;
    }
    
    bool dettach() {

        auto log = get_log();
        bool ret = true;
        
        int rc = munmap(data_, (size_t)capacity_);
        if (rc) {
            _war("Unmapping the memory failed; errno is %d", errno);
            ret = false;
        }        
        
        if(memory_fd > 0) {
            if (close(memory_fd) == -1) {
                _war("Closing memory's file descriptor failed; errno is %d", errno);
                ret = false;
            }
        }
        
        rc = sem_close(semaphore);
        if (rc) {
            _war("Closing the semaphore failed; errno is %d", errno);
            ret = false;
        }            
        
        attached_ = false;
        return ret;
    }
    
    
    int release() {
        auto log = get_log();
        int rc = sem_post(semaphore);

        if(rc) {
            _war("Releasing the semaphore failed; errno is %d", errno);
        }
        
        return rc;
    }
    
    int acquire() {

        auto log = get_log();
        if(! semaphore) {
            _war("Acquiring the semaphore failed; semaphore is not initialized");
            return -1;
        }
        int rc = sem_wait(semaphore);

        if(rc) {
            _war("Acquiring the semaphore failed; errno is %d", errno);
        }
        
        return rc;
    }
};


#endif