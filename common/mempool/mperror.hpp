#include <system_error>


#ifndef MPERROR_HPP
#define MPERROR_HPP

class mempool_bad_alloc : public std::runtime_error {
public:
    size_t block_size {0};
    explicit mempool_bad_alloc(const char* e) : std::runtime_error(e) {};
    mempool_bad_alloc(const char* e, size_t block_size) : std::runtime_error(e), block_size(block_size) {};

    [[nodiscard]] const char* what() const noexcept override {

#ifndef BUILD_RELEASE
        std::cerr << "cannot allocate block of " << block_size << " bytes" << std::endl;
#endif
        return "cannot allocate from pool";
    }
};

#endif