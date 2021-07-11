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

        void add_worker();
        void worker();

        bool stop_signal_ = false;
        std::vector<std::thread> threads_;

        logan_lite log;

    public:
        threadedPoolFileWriter& operator=(threadedPoolFileWriter const&) = delete;
        threadedPoolFileWriter(poolFileWriter const&) = delete;

        static threadedPoolFileWriter* instance() {
            static threadedPoolFileWriter w = threadedPoolFileWriter();
            return &w;
        }

        std::mutex& queue_lock() { return  queue_lock_; }
        std::unordered_map<std::string, std::queue<std::string>>& queue() { return task_queue_; };
        std::queue<std::string>& task_files()  { return task_files_; };


        // write won't actually write to file, but will queue that task
        size_t write(std::string const &fnm, std::string const &str) override;

    private:
        // map of log messages
        std::unordered_map<std::string, std::queue<std::string>> task_queue_;

        // files to handle - worker thread will remove file he works on from *task_files_* and ads it to *active_files*
        std::queue<std::string> task_files_;
        std::mutex queue_lock_;

        // worker thread controlling mutex.
        std::mutex workload_mutex_;

    };

}

#endif //THREADEDPOOLWRITER_HPP
