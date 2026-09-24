#pragma once

#include <atomic>
#include <cstdint>
#include <ctime>
#include <sstream>
#include <string>

#include <log/loggermac.hpp>

namespace socle {

// Lightweight identity for runtime/session objects. Unlike sobject this class
// does not register instances globally and therefore has no process-wide lock.
class session_object {
public:
    using oid_type = std::uint64_t;

    session_object() noexcept : oid_(next_oid()), created_(std::time(nullptr)) {}
    virtual ~session_object() = default;

    [[nodiscard]] oid_type oid() const noexcept { return oid_; }
    [[nodiscard]] std::time_t age() const noexcept { return std::time(nullptr) - created_; }
    virtual std::string to_string(int verbosity) const {
        std::stringstream ss;
        ss << c_type() << "-" << oid();
        return ss.str();
    }

    [[nodiscard]] inline std::string str() const { return to_string(6); }
    TYPENAME_BASE("session_object")

private:
    static oid_type next_oid() noexcept {
        static constexpr oid_type id_start = 0xCABA1ACABA1AULL;
        static constexpr oid_type id_key = 0x3453ABC3450FULL;
        static std::atomic<oid_type> current{id_start};
        return id_key ^ current.fetch_add(1, std::memory_order_relaxed);
    }

    oid_type oid_;
    std::time_t created_;
};

} // namespace socle
