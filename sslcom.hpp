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
#include <log/logger.hpp>

// Threading support

struct CompatThreading {
    #if defined (_POSIX_THREADS)
    // POSIX_THREADS is normally defined in unistd.h if pthreads are available on your platform.
    //
    //     #define MUTEX_TYPE pthread_mutex_t
    //     #define MUTEX_SETUP(x) pthread_mutex_init(&(x), nullptr)
    //     #define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
    //     #define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
    //     #define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
    //     #define THREAD_ID pthread_self( )

    using MUTEX_TYPE = std::mutex;

    // This array will store all of the mutexes available to OpenSSL.
    static MUTEX_TYPE*& mutex_buf() { static MUTEX_TYPE* ptr {nullptr}; return ptr; };

    inline static void MUTEX_SETUP(MUTEX_TYPE& x) {};
    inline static void MUTEX_CLEANUP(MUTEX_TYPE& x) {};
    inline static void MUTEX_LOCK (MUTEX_TYPE& x) { x.lock(); };
    inline static void MUTEX_UNLOCK(MUTEX_TYPE& x) { x.unlock(); }
    #else
    #error You must define mutex operations appropriate for your platform!

    #endif
    struct CRYPTO_dynlock_value {
        MUTEX_TYPE mutex;
    };

    static int THREAD_setup();
    static int THREAD_cleanup ();
    static void locking_function ( int mode, int n, const char * file, int line );
    static unsigned long id_function ();

    static CRYPTO_dynlock_value* dyn_create_function(const char *file, int line);
    static void dyn_lock_function(int mode, CompatThreading::CRYPTO_dynlock_value *l, const char *file, int line);
    static void dyn_destroy_function(CompatThreading::CRYPTO_dynlock_value *l, const char *file, int line);
};

enum class ret_handshake { FATAL=-2, ERROR=-1, AGAIN=0, SUCCESS=1, BYPASS=2 };

namespace socle::ex {
        class SSL_clienthello_malformed : public std::exception {
        public:

            [[nodiscard]]
            const char *what () const noexcept override {
                return "malformed ClientHello in peer communication";
            }
        };
    }

struct SSLComOptionsCert {
    // unknown issuers
    bool allow_unknown_issuer = false;
    bool allow_self_signed_chain = false;

    // common mistakes/misconfigs
    bool allow_not_valid = false;    //expired or not yet valid
    bool allow_self_signed = false;  //for depth 0

    bool failed_check_replacement = true; //if this is set to true, opt_allow* above will not cause session to terminate,
    //it will succeed to connect. It's then up to proxy to display replacement message.
    //currently works only for port 443, should be extended.
    bool failed_check_override = false;       //failed ssl replacement will contain option to temporarily allow the connection for the source IP.
    int  failed_check_override_timeout = 600; // if failed ssl override is active, this is the timeout.
    int  failed_check_override_timeout_type = 0; // 0 - hard timeout, 1 - idle timeout (reset timer on traffic)

    int client_cert_action = 1;                     // 0 - display a warning message and block, or drop the connection
    // 1 - pass, don't provide any certificate to server
    // 2 - bypass next connection

    bool mitm_cert_sni_search = false;      // allow search based on SNI
    bool mitm_cert_ip_search = false;      // allow search based on SNI
};

struct SSLComOptionsOcsp {
    bool stapling_enabled = false; // should we insist on OCSP response?
    int  stapling_mode = 0;        // 0 - allow all, log unverified. 1 - allow all, but don't allow unverified. 2 - as 1. but require all connections to have stapling response
    bool enforce_in_verify = false;     // stapling was not able to get status, we need use OCSP at the end of verify
    int  mode = 0;
};

struct SSLComCryptoFeatures {
    bool kex_dh = true;       // enable/disable pfs (DHE and ECDHE suites)
    bool kex_rsa = true;      // enable also kRSA
    bool allow_sha1 = true;   // should sha1 be enabled?
    bool allow_rc4 = false;   // should rc4 be enabled?
    bool allow_aes128 = true; // should we allow aes-128?
    bool no_tickets = false;  // enable abbreviated TLS handshake
};

struct SSLComOptions {
    // total bypass
    bool bypass = false;

    // Certificate Transparency support
    bool ct_enable = true;
    bool alpn_block = false;

    SSLComCryptoFeatures left;
    SSLComCryptoFeatures right;

    SSLComOptionsCert cert;
    SSLComOptionsOcsp ocsp;
};

struct SSLComCounters {
    int prof_accept_cnt=0;
    int prof_accept_bypass_cnt=0;
    int prof_connect_cnt=0;
    int write_want_read_cur=0; // immediate counter used to rescan socket
    int read_want_read_cur=0; // immediate counter used to rescan socket
    int prof_want_read_cnt=0;
    int write_want_write_cur=0; // immediate counter used to rescan socket
    int read_want_write_cur=0; // immediate counter used to rescan socket

    int prof_want_write_cnt=0;
    int prof_write_cnt=0;
    int prof_read_cnt=0;
    int prof_peek_cnt=0;

    int prof_accept_ok=0;
    int prof_connect_ok=0;
};

namespace socle::com::ssl {
    enum class staple_code_t {
        NOT_PROCESSED,
        MISSING_BODY,
        PARSING_FAILED,
        STATUS_NOK,
        GET_BASIC_FAILED,
        BASIC_VERIFY_FAILED,
        CERT_TO_ID_FAILED,
        NO_FIND_STATUS,
        INVALID_TIME,
        SUCCESS
    };

    enum class verify_origin_t {
        NONE,
        OCSP_STAPLING,
        OCSP_CACHE,
        OCSP,
        CRL_CACHE,
        CRL,
        EXEMPT
    };

    // verify status. Added also verify pseudo-status for client cert request.
    typedef enum {
        VRF_OK=0x1,
        VRF_UNKNOWN_ISSUER=0x2,
        VRF_SELF_SIGNED=0x4,
        VRF_INVALID=0x8,
            VRF_SELF_SIGNED_CHAIN=0x10,
            VRF_REVOKED=0x20,
            VRF_CLIENT_CERT_RQ=0x40,
            VRF_HOSTNAME_FAILED=0x80,
                VRF_CT_MISSING=0x100,
                VRF_CT_FAILED=0x200,
                    VRF_DEFERRED=0x1000,
                    VRF_EXTENDED_INFO=0x2000,
                    VRF_ALLFAILED=0x4000,
                    VRF_NOTTESTED=0x8000
    } verify_status_t;

    typedef enum {
        VRF_OTHER_SHA1_SIGNATURE=42,  // sha1 signature in the chain
        VRF_OTHER_CT_INVALID,         // some of CT entries are invalid
        VRF_OTHER_CT_FAILED,          // add this for each failed CT entry
    } vrf_other_values_t;
}

template <class L4Proto>
class baseSSLCom : public L4Proto, public virtual baseCom {

public:
    baseSSLCom();
    
    std::string to_string(int verbosity) const override;

    // get_peer_* return values as captured on the network
    // note: get_peer* don't necessarily return used values
    std::string get_sni() const { return sslcom_sni(); } //return copy of SNI
    std::string get_peer_id() const { return sslcom_peer_hello_id(); } //return copy of SNI
    std::string get_peer_alpn() const { return sslcom_peer_hello_alpn(); } //return copy of ALPN

    enum class client_state_t { NONE, INIT, PEER_CLIENTHELLO_WAIT , PEER_CLIENTHELLO_RECVD, CONNECTING, CONNECTED };
    client_state_t client_state_ = client_state_t::NONE;

    static int extdata_index() { return sslcom_ssl_extdata_index; };

    SSL* get_SSL() const { return sslcom_ssl; }
    X509* target_cert() const { return sslcom_target_cert; }
    X509* target_issuer() const { return sslcom_target_issuer; };
    X509* target_issuer_issuer() const { return sslcom_target_issuer_issuer; };

    // return ALPN (next protocol) really negotiated
    std::string const& alpn() { return sslcom_alpn_; }
protected:

	SSL_CTX* sslcom_ctx = nullptr;
	SSL*     sslcom_ssl = nullptr;
	BIO*	 sslcom_sbio = nullptr;
    int      sslcom_ret = 0;  // return value of last SSL_get_error() capable calls:
                              // SSL_connect, SSL_accept, SSL_do_handshake, SSL_read, SSL_peek,
                              // SSL_shutdown, SSL_write - and their respective _ex variants.
    
    //SSL external data offset, used by openssl callbacks
    static inline int sslcom_ssl_extdata_index {-1};
    
    //preferred key/cert pair to be loaded, instead of default one
    X509*     sslcom_pref_cert = nullptr;
    EVP_PKEY* sslcom_pref_key  = nullptr;
    SSL_CTX * sslcom_pref_ctx  = nullptr;

#ifndef USE_OPENSSL300
    //ECDH parameters
    EC_KEY *sslcom_ecdh = nullptr;
#endif

    //Peer information
    X509* sslcom_target_cert = nullptr;
    X509* sslcom_target_issuer = nullptr;
    X509* sslcom_target_issuer_issuer = nullptr;
    
	// states of read/writes
	int sslcom_read_blocked_on_write = 0;
	
    int sslcom_write_blocked_on_read = 0;
    int sslcom_write_blocked_on_write = 0;

    //handshake pending flag
	bool sslcom_waiting=true;

    // fatal signalling - no SSL_Shutdown must be called
    bool sslcom_fatal=false;
    
    //set if we are server/client
	bool sslcom_server_=false;
    

    bool handshake_peer_client(); // check if peer received already ClientHello
    ret_handshake handshake();
        void handshake_dia_error2(int op_code, int err, unsigned int err2);
        int handshake_client();
        int handshake_server();

    // SNI
    struct timeval timer_start{};
    
    //SSL_write or SSL_read checked timer. Successful read will reset also write timer and vice versa.
    struct timeval timer_write_timeout{};
    struct timeval timer_read_timeout{};
        
    //if we are actively waiting for something, it doesn't make sense to process peer events (which creates unnecessary load)
    inline bool unmonitor_peer() { 
        if(peer()) { 
            auto* p = dynamic_cast<baseSSLCom*>(peer());
            if(p != nullptr) {
                unset_monitor(p->socket());
                return true; 
            }
        } 
        return false; 
    }
    inline bool monitor_peer() { 
        if(peer()) { 
            auto* p = dynamic_cast<baseSSLCom*>(peer());
            if(p != nullptr) {
                set_monitor(p->socket());
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

    std::string sslcom_sni_;
    std::string sslcom_sni() const { return sslcom_sni_; }
    std::string& sslcom_sni() { return sslcom_sni_; }

    std::string sslcom_peer_hello_alpn_;
    std::string sslcom_peer_hello_alpn() const { return sslcom_peer_hello_alpn_; }
    std::string& sslcom_peer_hello_alpn() { return sslcom_peer_hello_alpn_; }

    std::string sslcom_alpn_;

    std::string sslcom_peer_hello_id_;
    std::string sslcom_peer_hello_id() const { return sslcom_peer_hello_id_; }
    std::string& sslcom_peer_hello_id() { return sslcom_peer_hello_id_; }

    std::shared_ptr<std::vector<std::string>> sni_filter_to_bypass_;
    bool sni_filter_to_bypass_matched = false;
    
    //try to set peer's key/certificate from cache (succeeds if peer haven't yet started ssl handshake and if there is cert in the cache).
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
    
    bool sslcom_refcount_incremented_ = false;
public:    
    // debug counters
    static inline std::atomic_int counter_ssl_connect {0};
    static inline std::atomic_int counter_ssl_accept {0};
    
    //threading once flag to init essential SSL hooks and locks.
    static inline std::once_flag openssl_thread_setup_done;
    
    // init factory and default CTX
    static void certstore_setup();
    static inline std::once_flag certstore_setup_done;


    // certificate store common across all SSCom instances
    static inline SSLFactory* factory_ {nullptr};
    static SSLFactory* factory() { return factory_; };
    static void factory(SSLFactory* c) { delete factory_; factory_ = c; };
	
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

    bool is_server() const  { return sslcom_server_; }
protected:
    void is_server(bool b) { sslcom_server_ = b; }
public:

    bool is_verify_status_opt_allowed();
    static int check_server_dh_size(SSL* ssl);
    unsigned long log_if_error(unsigned int level, const char* prefix);
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
    void upgraded(bool b) { if(upgraded() && b) { _not("double upgrade detected"); } auto_upgraded_ = b; }
    
    // set if waiting() should wait for peer hello.
    bool should_wait_for_peer_hello() { return should_wait_for_peer_hello_; }
    void should_wait_for_peer_hello(bool b) { should_wait_for_peer_hello_ = b; }
    std::shared_ptr<std::vector<std::string>>& sni_filter_to_bypass() { return sni_filter_to_bypass_; }
    
    int connect( const char* host, const char* port) override;
	ssize_t read (int _fd, void* _buf, size_t _n, int _flags ) override;
	ssize_t write (int _fd, const void* _buf, size_t _n, int _flags ) override;
	
	void cleanup() override;

    bool com_status() override;
    
    
    void shutdown(int _fd) override;
    ~baseSSLCom() override {
        if(sslcom_refcount_incremented_) {
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

#ifndef USE_OPENSSL300
        if(sslcom_ecdh != nullptr) {
            EC_KEY_free(sslcom_ecdh);
            sslcom_ecdh = nullptr;
        }
#endif

        if(sslcom_target_cert != nullptr) X509_free(sslcom_target_cert);
        if(sslcom_target_issuer != nullptr) X509_free(sslcom_target_issuer);
        if(sslcom_target_issuer_issuer != nullptr) X509_free(sslcom_target_issuer_issuer);
        
    };
    
   
public:

    SSLComCounters counters;
    SSLComOptions opt;

    using verify_origin_t = com::ssl::verify_origin_t;
    using staple_code_t = com::ssl::staple_code_t;
    using verify_status_t = com::ssl::verify_status_t;
    using vrf_other_values_t = com::ssl::vrf_other_values_t;

    static const int rescan_threshold_read = 30;
    static const int rescan_threshold_write = 30;

    bool bypass_me_and_peer();
    static inline const char* ci_def_filter
        = "HIGH RC4 !aNULL !eNULL !LOW !3DES !MD5 !EXP !DSS !PSK !SRP !kECDH !CAMELLIA !IDEA !SEED @STRENGTH";

    int ocsp_cert_is_revoked = -1;
    [[maybe_unused]] static int certificate_status_ocsp_check(baseSSLCom* com);
    [[maybe_unused]] static int certificate_status_oob_check(baseSSLCom* com, int required);

    // helper event functions
    virtual std::string ssl_error_details() const;

    verify_origin_t verify_origin_ {verify_origin_t::NONE};
    [[nodiscard]] verify_origin_t verify_origin() const { return verify_origin_; }

    void verify_origin(verify_origin_t v) { verify_origin_ = v; }
    static std::string verify_origin_str(verify_origin_t const& v);

    static std::pair<staple_code_t, int> check_revocation_stapling(std::string const& name, baseSSLCom*, SSL* ssl);

    using vrf_other_list = std::vector<short>;
    vrf_other_list vrf_other_;

    vrf_other_list& verify_extended_info() { return vrf_other_; }

    [[maybe_unused]] inline void verify_reset(verify_status_t s) { verify_status_ = s; }
    [[maybe_unused]] inline int verify_get() const { return static_cast<int>(verify_status_); }
    [[maybe_unused]] inline bool verify_bitcheck(unsigned int s) const { return (flag_check(verify_status_, s)); }
    [[maybe_unused]] inline void verify_bitset(unsigned int s) {
        flag_set(&verify_status_, s);
        _dia("verify_bitset: set 0x%04x: result 0x%04x", s, verify_status_);
    }
    [[maybe_unused]] inline void verify_bitreset(unsigned int s) {
        verify_status_ = flag_reset(verify_status_, s);
        _dia("verify_bitreset: set 0x%04x: result 0x%04x", s, verify_status_);
    }
    [[maybe_unused]] inline void verify_bitflip(unsigned int s)  {
        verify_status_ = flag_flip(verify_status_, s);
        _dia("verify_bitflip: set 0x%04x: result 0x%04x", s, verify_status_);
    }


    static int ct_verify_callback(const CT_POLICY_EVAL_CTX *ctx, const STACK_OF(SCT) *scts, void *arg);

    static inline int SSLCOM_CLIENTHELLO_TIMEOUT = 3*1000; //in ms
    static inline int SSLCOM_WRITE_TIMEOUT = 60*1000;      //in ms
    static inline int SSLCOM_READ_TIMEOUT = 60*1000;       //in ms

public:
    static logan_lite& log_cb_info() { static logan_lite l_("com.tls.cb.info"); return l_; };
    static logan_lite& log_cb_msg() { static logan_lite l_("com.tls.cb.msg"); return l_; };
    static logan_lite& log_cb_verify() { static logan_lite l_("com.tls.cb.verify"); return l_; };
    static logan_lite& log_cb_ccert() { static logan_lite l_("com.tls.cb.ccert"); return l_; };
    static logan_lite& log_cb_session() { static logan_lite l_("com.tls.cb.session"); return l_; };
    static logan_lite& log_cb_ct() { static logan_lite l_("com.tls.cb.ct"); return l_; };
    static logan_lite& log_cb_dh() { static logan_lite l_("com.tls.cb.dh"); return l_; };
    static logan_lite& log_cb_ecdh() { static logan_lite l_("com.tls.cb.ecdh"); return l_; };
    static logan_lite& log_cb_alpn() { static logan_lite l_("com.tls.cb.alpn"); return l_; };

    static logan_lite& log_ocsp() { static logan_lite l_("com.tls.ocsp"); return l_; };
    static logan_lite& log_ssl() { static logan_lite l_("com.tls"); return l_; };

    static SSL_SESSION *server_get_session_callback(SSL *ssl, const unsigned char *, int, int *);
    static int new_session_callback(SSL *ssl, SSL_SESSION *session);
    static void ssl_keylog_callback(const SSL *ssl, const char *line);
    static void ssl_msg_callback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg);
    static void ssl_info_callback(const SSL *s, int where, int ret);
    #ifndef USE_OPENSSL300
    static DH* ssl_dh_callback(SSL* s, int is_export, int key_length);
    #endif

    #ifndef USE_OPENSSL11
    static EC_KEY* ssl_ecdh_callback(SSL* s, int is_export, int key_length);
    #endif
    static int status_resp_callback(SSL *s, void *arg);
    static int ssl_client_cert_callback(SSL *ssl, X509 **x509, EVP_PKEY **pkey);
    static int ssl_client_vrfy_callback(int ok, X509_STORE_CTX *ctx);
    static int ssl_alpn_select_callback(SSL *s, const unsigned char **out, unsigned char *outlen,
                                        const unsigned char *in, unsigned int inlen,
                                        void *arg);

    void report_certificate_problem(X509* err_cert, int err_code) const;

    TYPENAME_OVERRIDE("SSLCom")
    DECLARE_LOGGING(to_string)

private:
    logan_lite& log = log_ssl();

    unsigned int verify_status_ = verify_status_t::VRF_NOTTESTED;

    // experimental switch to save SESSION data for left connections - WIP code
    static inline bool EXP_left_session_cache_enabled = false;
};

using SSLCom = baseSSLCom<TCPCom>;
using  DTLSCom = baseSSLCom<UDPCom>;


namespace socle::com::ssl {
    const char* SCT_validation_status_str(sct_validation_status_t const& st);
    std::string connection_name(baseCom const* com, bool reverse);
}


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
    int Z_is_one;               /* enable optimized point arithmetic for
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

#endif //SSLCOM_HPP

#include <sslcom.tpp>

