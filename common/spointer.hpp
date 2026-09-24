#pragma once

#include <atomic>
#include <set>
#include <vector>

namespace socle {

template <class T> class sref;

template <class T>
class spointer {
public:
    spointer() = default;
    explicit spointer(T* ptr): pointer_(ptr) {}
    virtual ~spointer() { delete pointer_; }
    unsigned int usage() const { return count_.load(); }
    bool valid() const { return pointer_ != nullptr; }
    void invalidate() { delete pointer_; pointer_ = nullptr; count_ = 0; }
    T* operator->() const { return pointer_; }
    T& operator*() const { return *pointer_; }
    T* ptr() const { return pointer_; }
    void ptr(T* p) { invalidate(); pointer_ = p; }
    spointer& operator=(spointer const&) = delete;
    spointer(spointer const&) = delete;

private:
    T* pointer_ = nullptr;
    std::atomic_int32_t count_ = 0;
    void use() { count_++; }
    void unuse() { if (count_ > 0) count_--; }
    friend class sref<T>;
};

template <class T>
class sref {
public:
    sref() = default;
    explicit sref(spointer<T>* r): reference_(r) { if (r) r->use(); }
    explicit sref(spointer<T>& r): reference_(&r) { r.use(); }
    sref(sref const& other): reference_(other.reference_) { if (reference_) reference_->use(); }
    ~sref() { unref(); }
    sref& operator=(sref const& other) {
        if (this != &other) { unref(); reference_ = other.reference_; if (reference_) reference_->use(); }
        return *this;
    }
    void unref() { if (reference_) { reference_->unuse(); reference_ = nullptr; } }
    spointer<T>* ref() { return reference_; }
    void ref(spointer<T>* n) { unref(); reference_ = n; if (n) n->use(); }
    void ref(spointer<T>& n) { ref(&n); }
    T* refval() { return reference_ ? reference_->pointer_ : nullptr; }

private:
    spointer<T>* reference_ = nullptr;
};

using spointer_vector_string = spointer<std::vector<std::string>>;
using spointer_vector_int = spointer<std::vector<int>>;
using spointer_set_int = spointer<std::set<int>>;
using sref_vector_string = sref<std::vector<std::string>>;

} // namespace socle
