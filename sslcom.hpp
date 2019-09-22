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

#ifndef SSLCOM_HPP
#define SSLCOM_HPP

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

#include <sobject.hpp>
#include <buffer.hpp>
#include <basecom.hpp>
#include <tcpcom.hpp>
#include <udpcom.hpp>
#include <sslcertstore.hpp>
#include <sslcertval.hpp>
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
unsigned long id_function ();


#pragma GCC diagnostic pop 
#pragma GCC diagnostic pop 

int THREAD_setup ();
int THREAD_cleanup ();

struct CRYPTO_dynlock_value
{
    MUTEX_TYPE mutex;
};


extern int SSLCOM_CLIENTHELLO_TIMEOUT;
extern int SSLCOM_READ_TIMEOUT;
extern int SSLCOM_WRITE_TIMEOUT;

enum class ret_handshake { ERROR=-1, AGAIN=0, SUCCESS=1, BYPASS=2 };

template <class L4Proto>
class baseSSLCom : public L4Proto, public virtual baseCom {

public:
    baseSSLCom();
    
    virtual std::string& to_string();
    std::string get_peer_sni() { return sslcom_peer_hello_sni().c_str(); } //return copy of SNI
    
protected:

    logan_attached<baseSSLCom<L4Proto>> log;

	SSL_CTX* sslcom_ctx = nullptr;
	SSL*     sslcom_ssl = nullptr;
	BIO*	 sslcom_sbio = nullptr;
    
    //SSL external data offset, used by openssl callbacks
    static int sslcom_ssl_extdata_index;
    
    //preferred key/cert pair to be loaded, instead of default one
    X509*     sslcom_pref_cert = nullptr;
    EVP_PKEY* sslcom_pref_key  = nullptr;
	
    //ECDH parameters
    EC_KEY *sslcom_ecdh = nullptr;
    
    //Peer information
    X509* sslcom_target_cert = nullptr;
    X509* sslcom_target_issuer = nullptr;
    X509* sslcom_target_issuer_issuer = nullptr;
    
	// states of read/writes
	int sslcom_read_blocked_on_write = 0;
	
        int sslcom_write_blocked_on_read=0;
        int sslcom_write_blocked_on_write=0;
        
	int sslcom_read_blocked = 0;
	
    //handshake pending flag
	bool sslcom_waiting=true;
    
    //set if we are server/client
	bool sslcom_server_=false;
    
	int sslcom_fd=0;



    bool handshake_peer_client(); // check if peer received already ClientHello
    ret_handshake handshake();
        void handshake_dia_error2(int op_code, int err, unsigned int err2);
        int handshake_client();
        int handshake_server();

    // SNI
    struct timeval timer_start;
    
    //SSL_write or SSL_read checked timer. Successful read will reset also write timer and vice versa.
    struct timeval timer_write_timeout;
    struct timeval timer_read_timeout;
        
    //if we are actively waiting for something, it doesn't make sense to process peer events (which creates unnecessary load)
    inline bool unmonitor_peer() { 
        if(peer()) { 
            auto* p = dynamic_cast<baseSSLCom*>(peer());
            if(p != nullptr) {
                unset_monitor(p->sslcom_fd); 
                return true; 
            }
        } 
        return false; 
    }
    inline bool monitor_peer() { 
        if(peer()) { 
            auto* p = dynamic_cast<baseSSLCom*>(peer());
            if(p != nullptr) {
                set_monitor(p->sslcom_fd); 
                return true; 
            }
        } 
        return false; 
    } 

    //if enabled, upgrade_client_socket or upgrade_server_socket are called automatically
    //during waiting().
    bool auto_upgrade_ = true;
    bool auto_upgraded_ = false;
    
    //it's waiting for it's usage or removal
	char* ssl_waiting_host = nullptr;
	
    // return true if peer already received client hello. For server side only (currently). 
    inline bool sslcom_peer_hello_received() { return sslcom_peer_hello_received_; }
    void sslcom_peer_hello_received(bool b) { sslcom_peer_hello_received_ = b; }
    
    //set to true if we should wait for peer's hello
    bool should_wait_for_peer_hello_ = false;
    //peeks peer socket for client_hello. For server side only (currently).
    bool waiting_peer_hello();
    
    //parses peer hello and stores interesting data (e.g. SNI information). For server side only (currently).
    int parse_peer_hello();
    unsigned short parse_peer_hello_extensions(buffer& b, unsigned int curpos);
    
    bool sslcom_peer_hello_received_ = false;
    buffer sslcom_peer_hello_buffer;

    std::string sslcom_peer_hello_sni_;
    std::string& sslcom_peer_hello_sni() { return sslcom_peer_hello_sni_; }
    socle::sref_vector_string sni_filter_to_bypass_;
    bool sni_filter_to_bypass_matched = false;
    
    //try to set peer's key/certificate from cache (succeeds if peer haven't yet started ssl handhake and if there is cert in the cache).
    //For server side only.
    bool enforce_peer_cert_from_cache(std::string & subj);
    //it's set to true if we used cached cert
    bool sslcom_peer_sni_shortcut = false;
    
    
    // is the socket up or not
    bool sslcom_status_ = false;
    inline bool sslcom_status() { return sslcom_status_; }
    inline void sslcom_status(bool b) { sslcom_status_ = b; }

    std::string flags_str() override;
private:
    typedef enum { HSK_REUSED = 0x4 } sslcom_flags;
    unsigned long flags_ = 0;
    
    bool sslcom_refcount_incremented__ = false;
public:    
    // debug counters
    static int counter_ssl_connect;
    static int counter_ssl_accept;
    
    //threading once flag to init essential SSL hooks and locks.
    static std::once_flag openssl_thread_setup_done;
    
    // certificate store common across all SSCom instances
    static SSLFactory* sslcom_certstore_;
    // init certstore and default CTX
    static void certstore_setup();
    static std::once_flag certstore_setup_done;    

    static SSLFactory* certstore() { return sslcom_certstore_; };
    static void certstore(SSLFactory* c) { delete sslcom_certstore_; sslcom_certstore_ = c; };
	
    //called just once
	void static_init() override;
    
    //com has to be init() before used
	void init(baseHostCX* owner) override;
    baseCom* replicate() override { return new baseSSLCom(); } ;

    //initialize callbacks. Basically it sets external data for SSL object.
    void init_ssl_callbacks();

    
    //free old SSL (if present), load default cert, set SSL options and set callbacks - no active communication.
	virtual void init_client();
	int upgrade_client_socket(int s);
    
    virtual void init_server();
    int upgrade_server_socket(int s);
    
    bool sslkeylog = false;
    void dump_keys();

    bool is_server() { return sslcom_server_; }
protected:
    void is_server(bool b) { sslcom_server_ = b; }
public:    

    static void ssl_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
    static void ssl_info_callback(const SSL *s, int where, int ret);
    static DH* ssl_dh_callback(SSL* s, int is_export, int key_length);
    static EC_KEY* ssl_ecdh_callback(SSL* s, int is_export, int key_length);
    static int ocsp_resp_callback(SSL *s, void *arg);
    static int ssl_client_cert_callback(SSL *ssl, X509 **x509, EVP_PKEY **pkey);
    static int ssl_client_vrfy_callback(int ok, X509_STORE_CTX *ctx);
    static int check_server_dh_size(SSL* ssl);
    long log_if_error(unsigned int level, const char* prefix);
    static long log_if_error2(unsigned int level, const char* prefix);
    void log_profiling_stats(unsigned int level);
    
	virtual bool check_cert(const char*);
    virtual bool store_session_if_needed();
    virtual bool load_session_if_needed();
	
	bool readable (int s) override;
	bool writable (int s) override;
	
	void accept_socket (int sockfd) override;
    void delay_socket (int sockfd) override;
    
    bool auto_upgrade() { return auto_upgrade_; }
    void auto_upgrade(bool b) { auto_upgrade_ = b; }
    bool upgraded() { return auto_upgraded_; }
    void upgraded(bool b) { if(upgraded() && b) { NOTS___("double upgrade detected"); } auto_upgraded_ = b; }
    
    // set if waiting() should wait for peer hello.
    bool should_wait_for_peer_hello() { return should_wait_for_peer_hello_; }
    void should_wait_for_peer_hello(bool b) { should_wait_for_peer_hello_ = b; }
    socle::sref_vector_string& sni_filter_to_bypass() { return sni_filter_to_bypass_; }
    
    int connect ( const char* host, const char* port, bool blocking = false ) override;
	int read ( int __fd, void* __buf, size_t __n, int __flags ) override;
	int write ( int __fd, const void* __buf, size_t __n, int __flags ) override;
	
	void cleanup() override;

    bool com_status() override;
    
    
    void shutdown(int __fd) override;
    ~baseSSLCom() override {
        if(sslcom_refcount_incremented__) {
#ifdef USE_OPENSSL11
            EVP_PKEY_free(sslcom_pref_key);
            X509_free(sslcom_pref_cert);
#else
            CRYPTO_add(&sslcom_pref_key->references,-1,CRYPTO_LOCK_EVP_PKEY);
            CRYPTO_add(&sslcom_pref_cert->references,-1,CRYPTO_LOCK_X509);
#endif
        }        
        
        if(sslcom_ssl != nullptr) {
            SSL_free(sslcom_ssl);
            sslcom_ssl = nullptr;
        }
        
        if(sslcom_ecdh != nullptr) {
            EC_KEY_free(sslcom_ecdh);
            sslcom_ecdh = nullptr;
        }

        if(sslcom_target_cert != nullptr) X509_free(sslcom_target_cert);
        if(sslcom_target_issuer != nullptr) X509_free(sslcom_target_issuer);
        if(sslcom_target_issuer_issuer != nullptr) X509_free(sslcom_target_issuer_issuer);
        
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
    bool bypass_me_and_peer();
    
    static std::string ci_def_filter;
    
    bool opt_left_kex_dh = true;       // enable/disable pfs (DHE and ECDHE suites)
    bool opt_left_kex_rsa = true;      // enable also kRSA
    bool opt_left_allow_sha1 = true;   // should sha1 be enabled?
    bool opt_left_allow_rc4 = false;   // should rc4 be enabled?
    bool opt_left_allow_aes128 = true; // should we allow aes-128?
    bool opt_left_no_tickets = false;  // enable abbreviated TLS handshake
    
    
                                       // the same as above, for right side
    bool opt_right_kex_dh = true;
    bool opt_right_kex_rsa = true;
    bool opt_right_allow_sha1 = true;
    bool opt_right_allow_rc4 = false;
    bool opt_right_allow_aes128 = true;
    bool opt_right_no_tickets = false;
    
    bool opt_ocsp_stapling_enabled = false; // should we insist on OCSP response?
    int  opt_ocsp_stapling_mode = 0;        // 0 - allow all, log unverified. 1 - allow all, but don't allow unverified. 2 - as 1. but require all connections to have stapling reponse
    bool opt_ocsp_enforce_in_verify = false;     // stapling was not able to get status, we need use OCSP at the end of verify
    #define SOCLE_OCSP_STAP_MODE_LOOSE   0
    #define SOCLE_OCSP_STAP_MODE_STRICT  1
    #define SOCLE_OCSP_STAP_MODE_REQUIRE 2 

    int ocsp_cert_is_revoked = -1;
    
    int opt_ocsp_mode = 0;
    static int ocsp_explicit_check(baseSSLCom* com);
    static int ocsp_resp_callback_explicit(baseSSLCom* com, int required);
    
    // unknown issuers
    bool opt_allow_unknown_issuer = false;
    bool opt_allow_self_signed_chain = false;
    
    // common mistakes/misconfigs
    bool opt_allow_not_valid_cert = false;    //expired or not yet valid
    bool opt_allow_self_signed_cert = false;  //for depth 0
    
    bool opt_failed_certcheck_replacement = true; //if this is set to true, opt_allow* above will not cause session to terminate,
                                                  //it will succeed to connect. It's then up to proxy to display replacement message.
                                                  //currently works only for port 443, should be extended.
    bool opt_failed_certcheck_override = false;       //failed ssl replacement will contain option to temporarily allow the connection for the source IP.
    int  opt_failed_certcheck_override_timeout = 600; // if failed ssl override is active, this is the timeout.
    int  opt_failed_certcheck_override_timeout_type = 0; // 0 - hard timeout, 1 - idle timeout (reset timer on traffic)
    
    int opt_client_cert_action = 1;                    // 0 - display a warning message and block, or drop the connection
                                                        // 1 - pass, don't provide any certificate to server
                                                        // 2 - bypass next connection
    
    // verify status. Added also verify pseudostatus for client cert request.
    typedef enum {  VERIFY_OK=0x0, 
                    UNKNOWN_ISSUER=0x1, 
                    SELF_SIGNED=0x2, 
                    INVALID=0x4, 
                    SELF_SIGNED_CHAIN=0x8, 
                                REVOKED=0x10, 
                                CLIENT_CERT_RQ=0x20,
                                HOSTNAME_FAILED=0x40
                                                        } verify_status_t;
                                
    unsigned int verify_status = VERIFY_OK;
    inline void verify_set(unsigned int s) { verify_status |= (verify_status_t)s; }
    inline bool verify_check(unsigned int s) const { return (verify_status & s); }
    inline int verify_get() const { return (int) verify_status; }

    DECLARE_C_NAME("SSLCom");
    DECLARE_LOGGING(to_string);  
};


typedef baseSSLCom<TCPCom> SSLCom;
typedef baseSSLCom<UDPCom> DTLSCom;



#ifdef USE_OPENSSL11
#else

/* 
 * this has been stolen from sources, since there is no ssl_locl.h header around! 
 * in case of issues, set SSL_LOCL_REDEF to 0
 */
#define SSL_LOCL_REDEF 1

#ifdef SSL_LOCL_REDEF
#define SSL_PKEY_NUM        8  

typedef struct cert_pkey_st {
  X509 *x509;
  EVP_PKEY *privatekey;
  /* Digest to use when signing */
  const EVP_MD *digest;
  } CERT_PKEY;


typedef struct ec_extra_data_st {
    struct ec_extra_data_st *next;
    void *data;
    void *(*dup_func) (void *);
    void (*free_func) (void *);
    void (*clear_free_func) (void *);
} EC_EXTRA_DATA;                /* used in EC_GROUP */
  
struct ec_point_st {
    const EC_METHOD *meth;
    /*
     * All members except 'meth' are handled by the method functions, even if
     * they appear generic
     */
    BIGNUM X;
    BIGNUM Y;
    BIGNUM Z;                   /* Jacobian projective coordinates: (X, Y, Z)
                                 * represents (X/Z^2, Y/Z^3) if Z != 0 */
    int Z_is_one;               /* enable optimized point arithmetics for
                                 * special case */
} /* EC_POINT */ ;

  
struct ec_key_st {
    int version;
    EC_GROUP *group;
    EC_POINT *pub_key;
    BIGNUM *priv_key;
    unsigned int enc_flag;
    point_conversion_form_t conv_form;
    int references;
    int flags;
    EC_EXTRA_DATA *method_data;
} /* EC_KEY */ ;  
  
typedef struct sess_cert_st
    {
    STACK_OF(X509) *cert_chain; /* as received from peer (not for SSL2) */

    /* The 'peer_...' members are used only by clients. */
    int peer_cert_type;

    CERT_PKEY *peer_key; /* points to an element of peer_pkeys (never NULL!) */
    CERT_PKEY peer_pkeys[SSL_PKEY_NUM];
    /* Obviously we don't have the private keys of these,
     * so maybe we shouldn't even use the CERT_PKEY type here. */

#ifndef OPENSSL_NO_RSA
    RSA *peer_rsa_tmp; /* not used for SSL 2 */
#endif
#ifndef OPENSSL_NO_DH
    DH *peer_dh_tmp; /* not used for SSL 2 */
#endif
#ifndef OPENSSL_NO_ECDH
    EC_KEY *peer_ecdh_tmp;
#endif

    int references; /* actually always 1 at the moment */
    } SESS_CERT;

  
#endif 


#endif //USE_OPENSSL11

#include <sslcom.tpp>
#endif
