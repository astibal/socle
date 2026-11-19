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

#include <chrono>
#include <unordered_map>

#include <buffer.hpp>
#include <traflog/threadedpoolwriter.hpp>

namespace socle {
    threadedPoolFileWriter::threadedPoolFileWriter() : poolFileWriter(false) {
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
        using clock = std::chrono::steady_clock;
        struct pending_flush {
            std::size_t bytes = 0;
            clock::time_point since = clock::now();
        };
        constexpr std::size_t flush_bytes = 256 * 1024;
        constexpr auto flush_interval = std::chrono::seconds(1);
        // Only this worker touches pending state. Flush after the byte limit
        // or deadline, including the final block when no more writes arrive.
        std::unordered_map<std::string, pending_flush> pending;
        while(true)
        {
            bool wait = false;
            {
                std::scoped_lock<std::mutex> l_(queue_lock_);
                if (queue().empty()) {
                    // Shutdown is complete only after every record accepted by
                    // write() has reached the backing file. Capture sessions
                    // can enqueue their final data and FIN blocks while static
                    // loggers are being destroyed.
                    if (stop_signal_.load()) break;
                    wait = true;
                } else {
                    auto& fnm = queue().front().first; // copy to ram is faster than to disk
                    auto& buf = queue().front().second;

                    if (queue().front().retire) {
                        poolFileWriter::flush(fnm);
                        poolFileWriter::close(fnm);
                        pending.erase(fnm);
                        queue().pop();
                        continue;
                    }
                    auto written = poolFileWriter::write(fnm, buf);
                    if (written) {
                        auto& dirty = pending[fnm];
                        dirty.bytes += written;
                        if (dirty.bytes >= flush_bytes) {
                            poolFileWriter::flush(fnm);
                            pending.erase(fnm);
                        }
                    }

                    queue().pop();
                }
            }
            // Check deadlines even with an empty queue, or with continuous
            // traffic to other files. New writes must not postpone the deadline.
            auto now = clock::now();
            for (auto it = pending.begin(); it != pending.end();) {
                if (now - it->second.since >= flush_interval) {
                    poolFileWriter::flush(it->first);
                    it = pending.erase(it);
                } else {
                    ++it;
                }
            }
            // we will wait if the queue was empty or handled by other workers
            if(wait) {
                ::usleep(1000);
            }
        }
        // Shutdown drains queued records first, then publishes the last bytes.
        for (auto const& item : pending) {
            poolFileWriter::flush(item.first);
        }
    }

    bool threadedPoolFileWriter::retire(std::string const& fnm) {
        std::scoped_lock lock(queue_lock_);
        task_queue_.emplace(fnm, buffer{}, true);
        return true;
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
        // A buffer copy can retain a non-owning view. The worker must own
        // these bytes after the caller returns.
        task_queue_.emplace(fnm, buffer(buf.data(), sz));

        return sz;
    }
}
