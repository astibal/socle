#include <sslcom.hpp>

int SSLCOM_CLIENTHELLO_TIMEOUT = 3*1000; //in ms
int SSLCOM_WRITE_TIMEOUT = 60*1000;      //in ms
int SSLCOM_READ_TIMEOUT = 60*1000;      //in ms

void CompatThreading::locking_function ( int mode, int n, const char * file, int line )  {

    if ( mode & CRYPTO_LOCK ) {
        MUTEX_LOCK ( mutex_buf()[n] );

        #ifdef MORE_LOGGING
            auto log = logan::create("com.ssl.threads");
            _dum("SSL threading: locked mutex %u for thread %u (%s:%d)",n,id_function(),file,line);
        #endif
    } else {
        MUTEX_UNLOCK ( mutex_buf()[n] );

        #ifdef MORE_LOGGING
            auto log = logan::create("com.ssl.threads");
            _dum("SSL threading: unlocked mutex %u from thread %u (%s:%d)",n,id_function(),file,line);
        #endif
    }
}

unsigned long CompatThreading::id_function () {

    static thread_local std::hash<std::thread::id> h;
    static thread_local unsigned long id = static_cast<unsigned long> (h(std::this_thread::get_id()));

    #ifdef MORE_LOGGING
        auto log = logan::create("com.ssl.threads");
        _dum("SSL threading: id_function: returning %u",id);
    #endif

    return id;
}


CompatThreading::CRYPTO_dynlock_value* CompatThreading::dyn_create_function(const char *file, int line) {

    auto* value = new CRYPTO_dynlock_value();

    MUTEX_SETUP(value->mutex);
    return value;
}

void CompatThreading::dyn_lock_function(int mode, CompatThreading::CRYPTO_dynlock_value *l, const char *file, int line) {

    if (mode & CRYPTO_LOCK)
        MUTEX_LOCK(l->mutex);
    else
        MUTEX_UNLOCK(l->mutex);
}

void CompatThreading::dyn_destroy_function(CompatThreading::CRYPTO_dynlock_value *l, const char *file, int line)  {
    MUTEX_CLEANUP(l->mutex);
    free(l);
}

int CompatThreading::THREAD_setup() {
    auto log = logan::create("com.ssl.threads");

    #ifndef USE_OPENSSL11
    mutex_buf() = new MUTEX_TYPE[CRYPTO_num_locks()];

    if ( !mutex_buf() ) {
        _fat("OpenSSL threading support: cannot allocate mutex buffer");
        return 0;
    }
    
    for (int i = 0; i < CRYPTO_num_locks(); i++ ) {
        MUTEX_SETUP ( CompatThreading::mutex_buf()[i] );
    }
    
    CRYPTO_set_id_callback ( CompatThreading::id_function );
    CRYPTO_set_locking_callback ( CompatThreading::locking_function );
    CRYPTO_set_dynlock_create_callback( CompatThreading::dyn_create_function );
    CRYPTO_set_dynlock_lock_callback( CompatThreading::dyn_lock_function );
    CRYPTO_set_dynlock_destroy_callback( CompatThreading::dyn_destroy_function );

    _dia("OpenSSL threading support: enabled");

    _dia("OpenSSL: loading error strings");
    SSL_load_error_strings();

    _dia("OpenSSL: loading algorithms");
    SSLeay_add_ssl_algorithms();

    #else
    _dia("OpenSSL: openssl1.1.x detected, using its own locking mechanisms.");
    #endif

    return 1;
}

int CompatThreading::THREAD_cleanup() {

    #ifndef USE_OPENSSL11

    if ( !mutex_buf() ) {
        return 0;
    }
    CRYPTO_set_id_callback (nullptr);
    CRYPTO_set_locking_callback (nullptr);
    CRYPTO_set_dynlock_create_callback(nullptr);
    CRYPTO_set_dynlock_lock_callback(nullptr);
    CRYPTO_set_dynlock_destroy_callback(nullptr);

    for ( int i = 0; i < CRYPTO_num_locks( ); i++ ) {
        MUTEX_CLEANUP ( mutex_buf()[i] );
    }
    
    delete[] mutex_buf();
    mutex_buf() = nullptr;
    #endif

    return 1;
}

