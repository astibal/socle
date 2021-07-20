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

#include <buffer.hpp>
#include <traflog/threadedpoolwriter.hpp>

namespace socle {
    threadedPoolFileWriter::threadedPoolFileWriter() {
        log = logan::create("socle.threadedPoolFileWriter");

        // add 2 workers.
        add_worker();
        add_worker();
    }

    threadedPoolFileWriter::~threadedPoolFileWriter() {
        stop_signal_ = true;
        for( auto& t: threads_) {
            if(t.joinable())
                t.join();
        }
    }


    void threadedPoolFileWriter::add_worker() {
        auto t = std::thread(&threadedPoolFileWriter::worker, this);
        threads_.emplace_back(std::move(t));
    }

    void threadedPoolFileWriter::worker() {
        :: pthread_setname_np(pthread_self(), "sx-wrt");
        while(! stop_signal_)
        {
            bool wait = false;
            std::string fnm;
            buffer to_write;
            {
                std::scoped_lock<std::mutex> l_(queue_lock_);
                if (queue().empty()) {
                    wait = true;
                } else {
                    fnm = queue().front().first; // copy to ram is faster than to disk
                    to_write.append(queue().front().second);
                    queue().pop();
                }
            }
            // we will wait if the queue was empty or handled by other workers
            if(wait) {
                ::usleep(1000);
            } else {
                poolFileWriter::write(fnm, to_write);
            }
        }
    }

    size_t threadedPoolFileWriter::write(std::string const &fnm, std::string const &str) {


        auto sz = str.size();

        std::scoped_lock<std::mutex> l_(queue_lock_);
        task_queue_.emplace(fnm, buffer(str.data(), sz));

        return sz;
    }

    size_t threadedPoolFileWriter::write(std::string const &fnm, buffer const &buf) {

        auto sz = buf.size();

        std::scoped_lock<std::mutex> l_(queue_lock_);
        task_queue_.emplace(fnm, buf);

        return sz;
    }
}