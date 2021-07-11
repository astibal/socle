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
        :: pthread_setname_np(pthread_self(), "sx-thwrt");
        while(! stop_signal_)
        {
            bool wait = false;
            std::string fnm;
            {
                std::scoped_lock<std::mutex> l_(queue_lock_);
                if (task_files_.empty()) {
                    wait = true;
                } else {
                    fnm = task_files_.front();
                    task_files_.pop();
                }
            }
            // we will wait if the queue was empty or handled by other workers
            if(wait || fnm.empty()) {
                ::usleep(1000);
            } else {
                // we work on 'fnm' file
                bool cont = true;
                do {
                    std::string msg;
                    {
                        // get the string
                        std::scoped_lock<std::mutex> l_(queue_lock_);

                        auto it = task_queue_.find(fnm);
                        if(it != task_queue_.end()) {
                            auto& myqueue = task_queue_[fnm];
                            if(! myqueue.empty()) {
                                msg = myqueue.front();
                                myqueue.pop();

                                // shortcut - if this was last element, dont continue
                                if(myqueue.empty()) {
                                    task_queue_.erase(fnm);
                                    cont = false;
                                }
                            } else {
                                // myqueue is empty
                                task_queue_.erase(fnm);
                                cont = false;
                            }

                        } else{
                            // fnm not it hash
                            cont = false;
                        }
                    }

                    // queue is now unlocked!!!
                    // OK - we get the string, let's write it to the stream
                    poolFileWriter::write(fnm, msg);

                } while(cont);
            }
        }
    }

    size_t threadedPoolFileWriter::write(std::string const &fnm, std::string const &str) {
        {
            // ad this file to tasks, but only if it's not already handled by worker
            std::scoped_lock<std::mutex> l_(queue_lock_);
            if(task_queue_.find(fnm) == task_queue_.end()) {
                task_files_.push(fnm);
            }
            task_queue_[fnm].push(str);
        }

        // we enqueued it, just returning its size
        return str.size();
    }
}