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

#include <iostream>
#include <string>
#include <mutex>
#include <memory>

#include <log/logger.hpp>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>


std::shared_ptr<LogMux> Log::get() {
    return instance()->lout_;
}

std::shared_ptr<LogMux> Log::default_logger() {
    static auto r = std::shared_ptr<LogMux>(new LogMux);
    return r;
}

std::string Log::level_name(unsigned int l) {

    if (l > Log::Log::levels.size() - 1) {
        return string_format("loglev-%d", l);
    } else {
        return Log::levels[l];
    }
}

void Log::set(std::shared_ptr<LogMux> l) {
    instance()->lout_ = l;
}


std::string ESC_ (const std::string &s) {
    std::string t = s;
    std::replace( t.begin(), t.end(), '%', '^');
    return t;
}

logger_profile::~logger_profile() {
    for(auto& [ optr, mptr ]: targets_) {
        if(optr) {
            optr->flush();
        }
    }
}

LogMux::remote_log_target::~remote_log_target() {
    if(fd >= 0) ::close(fd);
}

std::shared_ptr<const LogMux::remote_log_targets_t> LogMux::remote_targets_snapshot() const {
    return std::atomic_load(&remote_targets_snapshot_);
}

bool LogMux::add_remote_target(std::string_view name, int descriptor,
                               std::shared_ptr<logger_profile> profile) {
    const int owned_descriptor = ::fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
    if(owned_descriptor < 0) return false;

    auto target = std::make_shared<remote_log_target>(std::string(name), descriptor,
                                                      owned_descriptor, std::move(profile));
    std::scoped_lock update(remote_targets_update_mutex_);
    auto next = std::make_shared<remote_log_targets_t>();
    const auto current = remote_targets_snapshot();
    next->reserve(current->size() + 1);
    for(const auto& item : *current)
        if(item->source_fd != descriptor) next->push_back(item);
    next->push_back(std::move(target));
    std::atomic_store(&remote_targets_snapshot_,
                      std::static_pointer_cast<const remote_log_targets_t>(next));
    return true;
}

void LogMux::remove_remote_target(int descriptor) {
    std::scoped_lock update(remote_targets_update_mutex_);
    const auto current = remote_targets_snapshot();
    auto next = std::make_shared<remote_log_targets_t>();
    next->reserve(current->size());
    for(const auto& item : *current)
        if(item->source_fd != descriptor) next->push_back(item);
    std::atomic_store(&remote_targets_snapshot_,
                      std::static_pointer_cast<const remote_log_targets_t>(next));
}

std::shared_ptr<logger_profile> LogMux::remote_target_profile(int descriptor) const {
    const auto current = remote_targets_snapshot();
    for(const auto& item : *current)
        if(item->source_fd == descriptor) return item->profile;
    return {};
}

unsigned long get_usec() {
    auto now = std::chrono::system_clock::now();
    auto usec_total=
            std::chrono::duration_cast<std::chrono::microseconds>(
                    now.time_since_epoch()
            );

    auto usec   = (usec_total.count() % (1000 * 1000));
    return usec;
}

std::tm get_tm(time_t const& tt) {
    std::tm result{};

#ifndef _POSIX_C_SOURCE
    static std::mutex m;
    auto l_ = std::scoped_lock(m);
    result = *std::localtime(&tt);

    return result;
#else
    localtime_r(&tt, &result);
    return result;
#endif
}

bool LogMux::periodic_start(unsigned int s) {
	auto now = static_cast<unsigned long>(time(nullptr));

    last_period_status = now > static_cast<unsigned long>(last_period) + s;

	return last_period_status;
}


bool LogMux::periodic_end() {
	if (last_period_status) {
		time_t now = time(nullptr);
		last_period = now;

		return true;
	}

	return false;
}


bool LogMux::should_log_topic(loglevel& writer, loglevel& msg) {

    // writer loglevel
    unsigned int t = writer.topic();

    // if msg has set topic, we need to check what to do
    if(msg.topic() != 0) {
        if(msg.more() != nullptr) {
            if(msg.more()->exclusive_exact) {
                if(t != msg.topic()) {
                    return false;
                }
            }

            // Exclusive topic
            if (msg.more()->exclusive_topic) {
                if(t == iNON) return false;

                unsigned int l_area = 0xffff0000 | msg.topic();
                unsigned int t_area = 0xffff0000 | t;
                if(l_area != t_area) {
                    return false;
                }
            }
        }
    } else {
        // msg doesn't have any topic (== 0)
        if(t > 0) {

            // we don't want to write generic messages into specialized writer
            return false;
        }
    }

    return true;
}

size_t LogMux::write_log(loglevel level, std::string& sss) {
    bool really_dup = dup2_cout();

    // targets are ostream pointers
    for( auto const& [ target, mut ] : targets()) {


        const auto profile = target_profiles().find((uint64_t) target.get());
        if(profile == target_profiles().end() || !profile->second) continue;
        if(profile->second->level_ < level) continue;
        if (!should_log_topic(profile->second->level_,level)) continue;

        auto l_ = std::scoped_lock(*mut);
        *target << sss << std::endl;
    }

    const auto managed_targets = remote_targets_snapshot();
    for(const auto& target : *managed_targets) {
        const auto& profile = target->profile;
        if(!profile || profile->level_ < level || !should_log_topic(profile->level_, level)) continue;

        std::stringstream message;
        if(profile->logger_type == REMOTE_SYSLOG)
            message << string_format("<%d> ", profile->syslog_settings.prival());
        message << sss;
        if(profile->logger_type != REMOTE_SYSLOG) message << "\r\n";
        const auto output = message.str();
        if(output.empty()) continue;

        std::scoped_lock write(target->write_mutex);
        (void)::send(target->fd, output.data(), output.size(), MSG_DONTWAIT | MSG_NOSIGNAL);
    }


    if(level <= level_) {
        // if set, log extra to stdout/stderr
        if (really_dup) {
            std::ostream *o = &std::cout;

            if (level <= log::level::ERR) {
                o = &std::cerr;
            }
            *o << sss << std::endl;
        }
    }
    return sss.size();
}



bool LogMux::click_timer (const std::string &xname, int interval) {

	std::lock_guard<std::mutex> lck(mtx_timers);

	std::string name;
	auto myid = std::this_thread::get_id();
	std::stringstream ss;
	ss << myid;

	name += xname + "_th" + ss.str();

	auto r = timers.find(name);
	if (r != timers.end()) {
		// we found entry
		time_t l = r->second.last;
		int i = r->second.timeout;

		time_t now = ::time(nullptr);

		if( now > l + i) {
			(*r).second.last = now;
			return true;
		}
		else {
			return false;
		}

	} else {
		// we should establish a new timer
		time_t now = ::time(nullptr);
		timer_tt tt;
		tt.last = now;
		tt.timeout = interval;

		timers[name] = tt;

		return true;
	}
}

void Events::publish(const logan_events::EventCollector::Delivery& delivery) {
    // Prepare owned text before taking the shared history lock. This is a sink,
    // never a drain of CLI history, and does not inherit legacy event_block IDs.
    std::vector<std::pair<std::string, std::string>> prepared;
    for (const auto& batch : delivery.batches) {
        for (const auto& observation : batch.events) {
            std::ostringstream summary, detail;
            const auto& event = observation.event;
            const char* level = "notice";
            switch (event.level) {
                case logan_events::EventLevel::detail: level = "detail"; break;
                case logan_events::EventLevel::warning: level = "warning"; break;
                case logan_events::EventLevel::error: level = "error"; break;
                case logan_events::EventLevel::notice: break;
            }
            const auto now = time(nullptr);
            auto tm = get_tm(now);
            summary << std::put_time(&tm, "%y-%m-%d %H:%M:%S") << ": "
                    << level << ": " << event.message;
            if (!event.context.empty()) summary << " (" << event.context << ")";
            if (observation.count > 1) summary << " [x" << observation.count << "]";
            detail << event.message << '\n';
            if (!event.context.empty()) detail << event.context << '\n';
            for (const auto& [key, value] : batch.context.fields) {
                detail << key << ": " << value << '\n';
                if (key == "connection") summary << " [connection " << value << "]";
            }
            detail << "occurrences: " << observation.count << "\nspan_ms: "
                   << std::chrono::duration_cast<std::chrono::milliseconds>(
                          observation.last_seen - observation.first_seen).count() << '\n';
            if (!batch.context.detail.empty()) detail << batch.context.detail << '\n';
            prepared.emplace_back(summary.str(), detail.str());
        }
    }
    if (delivery.lost) {
        prepared.emplace_back("warning: event trail loss: " + std::to_string(delivery.lost),
                              "Trail overflow, collector overflow or processing failure.");
    }
    auto lock = std::scoped_lock(events_lock_);
    for (auto& [summary, detail] : prepared) {
        const auto id = ++event_count_;
        events_.emplace_back(id, std::move(summary));
        event_detail_db_.emplace(id, std::move(detail));
        while (events_.size() > events_max_) {
            const auto expired = events_.front().first;
            events_.pop_front();
            event_detail_db_.erase(expired);
        }
    }
}
