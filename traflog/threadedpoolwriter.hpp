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

#ifndef THREADEDPOOLWRITER_HPP
#define THREADEDPOOLWRITER_HPP

#include <unistd.h>
#include <queue>

#include <traflog/poolwriter.hpp>

namespace socle {

    class threadedPoolFileWriter : public poolFileWriter {

        explicit threadedPoolFileWriter();
        ~threadedPoolFileWriter() override;

        void run_worker();
        void worker();

        bool stop_signal_ = false;
        std::thread worker_thread_;

    public:
        using element_t = std::pair<std::string, buffer>;
        using queue_t = std::queue<element_t>;

        threadedPoolFileWriter& operator=(threadedPoolFileWriter const&) = delete;
        threadedPoolFileWriter(poolFileWriter const&) = delete;

        static threadedPoolFileWriter* instance() {
            static threadedPoolFileWriter w = threadedPoolFileWriter();
            return &w;
        }

        std::mutex& queue_lock() { return  queue_lock_; }
        queue_t& queue() { return task_queue_; };

        // write won't actually write to file, but will queue that task
        size_t write(std::string const &fnm, std::string const &str) override;
        size_t write(std::string const &fnm, buffer const &buf) override;
    private:
        logan_lite log;
        // map of log messages

        queue_t task_queue_;
        std::mutex queue_lock_;

        // worker thread controlling mutex.
        std::mutex workload_mutex_;

    };

}

#endif //THREADEDPOOLWRITER_HPP
