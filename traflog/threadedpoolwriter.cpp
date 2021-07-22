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

        run_worker();
    }

    threadedPoolFileWriter::~threadedPoolFileWriter() {
        stop_signal_ = true;
        if(worker_thread_.joinable())
                worker_thread_.join();
    }


    void threadedPoolFileWriter::run_worker() {
        worker_thread_= std::thread(&threadedPoolFileWriter::worker, this);
    }

    void threadedPoolFileWriter::worker() {
        :: pthread_setname_np(pthread_self(), "sx-wrt");
        while(! stop_signal_)
        {
            bool wait = false;
            {
                std::scoped_lock<std::mutex> l_(queue_lock_);
                if (queue().empty()) {
                    wait = true;
                } else {
                    auto& fnm = queue().front().first; // copy to ram is faster than to disk
                    auto& buf = queue().front().second;

                    poolFileWriter::write(fnm, buf);

                    queue().pop();
                }
            }
            // we will wait if the queue was empty or handled by other workers
            if(wait) {
                ::usleep(1000);
            } else {

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