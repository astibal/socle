#include <sslcom.hpp>

int SSLCOM_CLIENTHELLO_TIMEOUT = 3000; //in ms

void locking_function ( int mode, int n, const char * file, int line )  {

    if ( mode & CRYPTO_LOCK ) {
        MUTEX_LOCK ( mutex_buf[n] );
        DUM_("SSL threading: locked mutex %u for thread %u (%s:%d)",n,id_function(),file,line);
    } else {
        MUTEX_UNLOCK ( mutex_buf[n] );
        DUM_("SSL threading: unlocked mutex %u from thread %u (%s:%d)",n,id_function(),file,line);
    }
}

unsigned long id_function ( void ) {

    std::hash<std::thread::id> h;
    unsigned long id = ( unsigned long ) h(std::this_thread::get_id());

    DUM_("SSL threading: id_function: returning %u",id);

    return id;
}


static struct CRYPTO_dynlock_value * dyn_create_function(const char *file, int line) {

    struct CRYPTO_dynlock_value *value = new CRYPTO_dynlock_value();

    if (!value)
        return NULL;
    
    MUTEX_SETUP(value->mutex);
    return value;
}

static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line) {

    if (mode & CRYPTO_LOCK)
        MUTEX_LOCK(l->mutex);
    else
        MUTEX_UNLOCK(l->mutex);
}

static void dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                                 const char *file, int line)  {
    MUTEX_CLEANUP(l->mutex);
    free(l);
}


int THREAD_setup ( void ) {
    int i;
    mutex_buf = new MUTEX_TYPE[CRYPTO_num_locks()];

    if ( !mutex_buf ) {
        FATS_("OpenSSL threading support: cannot allocate mutex buffer");
        return 0;
    }
    
    for ( i = 0; i < CRYPTO_num_locks( ); i++ ) {
        MUTEX_SETUP ( mutex_buf[i] );
    }
    
    CRYPTO_set_id_callback ( id_function );
    CRYPTO_set_locking_callback ( locking_function );
    CRYPTO_set_dynlock_create_callback(dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);

    DIAS_("OpenSSL threading support: enabled");

    DIAS_("OpenSSL: loading error strings");
    SSL_load_error_strings();

    DIAS_("OpenSSL: loading algorithms");
    SSLeay_add_ssl_algorithms();

    return 1;
}

int THREAD_cleanup ( void ) {
    int i;
    if ( !mutex_buf ) {
        return 0;
    }
    CRYPTO_set_id_callback ( NULL );
    CRYPTO_set_locking_callback ( NULL );
    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);

    for ( i = 0; i < CRYPTO_num_locks( ); i++ ) {
        MUTEX_CLEANUP ( mutex_buf[i] );
    }
    
    delete[] mutex_buf;
    mutex_buf = NULL;
    return 1;
}

