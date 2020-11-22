#include <system_error>

class mempool_bad_alloc : public std::runtime_error {
public:
    int block_size {0};
    mempool_bad_alloc(const char* e) : std::runtime_error(e) {};
    mempool_bad_alloc(const char* e, int block_size) : std::runtime_error(e), block_size(block_size) {};
};