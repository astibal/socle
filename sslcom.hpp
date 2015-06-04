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

#ifndef SSHCOM_HPP
#define SSHCOM_HPP

#include <map>
#include <string>
#include <thread>

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <buffer.hpp>
#include <basecom.hpp>
#include <tcpcom.hpp>
#include <sslcertstore.hpp>
#include <logger.hpp>

// Threading support

#if defined(WIN32)
    #define MUTEX_TYPE HANDLE
    #define MUTEX_SETUP(x) (x) = CreateMutex(NULL, FALSE, NULL)
    #define MUTEX_CLEANUP(x) CloseHandle(x)
    #define MUTEX_LOCK(x) WaitForSingleObject((x), INFINITE)
    #define MUTEX_UNLOCK(x) ReleaseMutex(x)
    #define THREAD_ID GetCurrentThreadId( )
#elif defined (_POSIX_THREADS)
    /* _POSIX_THREADS is normally defined in unistd.h if pthreads are available
       on your platform. */
//     #define MUTEX_TYPE pthread_mutex_t
//     #define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
//     #define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
//     #define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
//     #define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
//     #define THREAD_ID pthread_self( )

    #define MUTEX_TYPE std::mutex
    #define MUTEX_SETUP(x) 
    #define MUTEX_CLEANUP(x) 
    #define MUTEX_LOCK(x) x.lock()
    #define MUTEX_UNLOCK(x) x.unlock()
#else
    #error You must define mutex operations appropriate for your platform!
#endif

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic push

#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic push

/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE* mutex_buf = nullptr;
void locking_function ( int mode, int n, const char * file, int line );
unsigned long id_function ( void );


#pragma GCC diagnostic pop 
#pragma GCC diagnostic pop 

int THREAD_setup ( void );
int THREAD_cleanup ( void );

struct CRYPTO_dynlock_value
{
    MUTEX_TYPE mutex;
};


class SSLCom : public TCPCom {

public:
    SSLCom();
    
protected:
	SSL_CTX* sslcom_ctx = NULL;
	SSL*     sslcom_ssl = NULL;
	BIO*	 sslcom_sbio = NULL;
    
    //SSL external data offset, used by openssl callbacks
    static int sslcom_ssl_extdata_index;
    
    //preferred key/cert pair to be loaded, instead of default one
    X509*     sslcom_pref_cert = NULL;
    EVP_PKEY* sslcom_pref_key  = NULL;
	
    //ECDH parameters
    EC_KEY *sslcom_ecdh = nullptr;
    
	// states of read/writes
	int sslcom_read_blocked_on_write=0;
	int sslcom_write_blocked_on_read=0;
	int sslcom_read_blocked=0;
	
    //handshake pending flag
	bool sslcom_waiting=true;
    
    //set if we are server/client
	bool sslcom_server_=false;
    
	int sslcom_fd=0;
    
    //handhake handler called from read/write - you will not want to use it directly
	int waiting();

    //if enabled, upgreade_client_socket or upgreade_server_socket are called automatically
    //during waiting().
    bool auto_upgrade_ = true;
    bool auto_upgraded_ = false;
    
    //it's waiting for it's usage or removal
	char* ssl_waiting_host = NULL;
	
    // return true if peer already received client hello. For server side only (currently). 
    inline bool sslcom_peer_hello_received() { return sslcom_peer_hello_received_; }
    void sslcom_peer_hello_received(bool b) { sslcom_peer_hello_received_ = b; }
    
    //set to true if we should wait for peer's hello
    bool should_wait_for_peer_hello_ = false;
    //peeks peer socket for client_hello. For server side only (currently).
    bool waiting_peer_hello();
    
    //parses peer hello and stores interesing data (e.g. SNI information). For server side only (currently).
    bool parse_peer_hello();
    unsigned short parse_peer_hello_extensions(buffer& b, unsigned int curpos);
    
    bool sslcom_peer_hello_received_ = false;
    buffer sslcom_peer_hello_buffer;
    std::string sslcom_peer_hello_sni_;
    
    //try to set peer's key/certificate from cache (succeeds if peer haven't yet started ssl handhake and if there is cert in the cache).
    //For server side only.
    bool enforce_peer_cert_from_cache(std::string & subj);
    //it's set to true if we used cached cert
    bool sslcom_peer_sni_shortcut = false;
    
    
    // is the socket up or not
    bool sslcom_status_ = false;
    inline bool sslcom_status() { return sslcom_status_; }
    inline void sslcom_status(bool b) { sslcom_status_ = b; }

public:    
    // debug counters
    static int counter_ssl_connect;
    static int counter_ssl_accept;
    
    //threading once flag to init essential SSL hooks and locks.
    static std::once_flag openssl_thread_setup_done;
    
    // certificate store common across all SSCom instances
    static SSLCertStore* sslcom_certstore_;
    // init certstore and default CTX
    static void certstore_setup(void);
    static std::once_flag certstore_setup_done;    
    //static SSL_CTX* client_ctx_setup();
    static SSL_CTX* client_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);
    static SSL_CTX* server_ctx_setup(EVP_PKEY* priv = nullptr, X509* cert = nullptr, const char* ciphers = nullptr);
    
    static SSLCertStore* certstore() { return sslcom_certstore_; };
    static void certstore(SSLCertStore* c) { if (sslcom_certstore_ != NULL) { delete sslcom_certstore_; }  sslcom_certstore_ = c; };
	
    //called just once
	virtual void static_init();
    
    //com has to be init() before used
	virtual void init(baseHostCX* owner);
    virtual baseCom* replicate() { return new SSLCom(); } ;
    virtual const char* name() { return "ssl"; };
    virtual const char* hr();
    std::string hr_;
    
    
    //initialize callbacks. Basically it sets external data for SSL object.
    void init_ssl_callbacks();
    
    //free old SSL (if present), load default cert, set SSL options and set callbacks - no active communication.
	virtual void init_client();
	int upgrade_client_socket(int s);
    
    virtual void init_server();
    int upgrade_server_socket(int s);

    bool is_server() { return sslcom_server_; }
protected:
    void is_server(bool b) { sslcom_server_ = b; }
public:    

    static void ssl_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
    static void ssl_info_callback(const SSL *s, int where, int ret);
    static DH* ssl_dh_callback(SSL* s, int is_export, int key_length);
    static EC_KEY* ssl_ecdh_callback(SSL* s, int is_export, int key_length);
    static int ssl_client_vrfy_callback(int ok, X509_STORE_CTX *ctx);
    long log_if_error(unsigned int level, const char* prefix);
    static long log_if_error2(unsigned int level, const char* prefix);
    
	virtual bool check_cert(const char*);
	
	virtual bool readable (int s);
	virtual bool writable (int s);
	
	virtual void accept_socket ( int sockfd	);
    virtual void delay_socket ( int sockfd );
    
    bool auto_upgrade() { return auto_upgrade_; }
    void auto_upgrade(bool b) { auto_upgrade_ = b; }
    bool upgraded() { return auto_upgraded_; }
    void upgraded(bool b) { if(upgraded() && b == true) { NOTS___("double upgrade detected"); } auto_upgraded_ = b; }
    
    // set if waiting() should wait for peer hello.
    bool should_wait_for_peer_hello() { return should_wait_for_peer_hello_; }
    void should_wait_for_peer_hello(bool b) { should_wait_for_peer_hello_ = b; }
    
    
    virtual int connect ( const char* host, const char* port, bool blocking = false );
	virtual int read ( int __fd, void* __buf, size_t __n, int __flags );
	virtual int write ( int __fd, const void* __buf, size_t __n, int __flags );
	
	virtual void cleanup();

    virtual bool com_status();
    
    virtual ~SSLCom() {
        if(sslcom_ecdh != nullptr) {
            EC_KEY_free(sslcom_ecdh);;
        }
    };
    
   
public:
    int prof_accept_cnt=0;
    int prof_accept_bypass_cnt=0;
    int prof_connect_cnt=0;
    int prof_want_read_cnt=0;
    int prof_want_write_cnt=0;
    int prof_write_cnt=0;
    int prof_read_cnt=0;
    int prof_peek_cnt=0;

    int prof_accept_ok=0;
    int prof_connect_ok=0;

    
    // total bypass
    bool opt_bypass = false;
    
    // enable/disable pfs (DHE and ECDHE suites)
    bool opt_pfs = true;
    
    // unknown issuers
    bool opt_allow_unknown_issuer = false;
    bool opt_allow_self_signed_chain = false;
    
    // common mistakes/misconfigs
    bool opt_allow_not_valid_cert = false;    //expired or not yet valid
    bool opt_allow_self_signed_cert = false;  //for depth 0

    int status_client_verify = -1;	      // -1 never ever done, everything else is status of processed verification
    
public:
    static unsigned int& log_level_ref() { return log_level; }
private:
    static unsigned int log_level;
};

#endif