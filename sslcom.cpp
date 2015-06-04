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

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tls1.h>
#include <openssl/x509_vfy.h>

#include <sslcom.hpp>
#include <sslcom_dh.hpp>
#include <logger.hpp>


#include <cstdio>
#include <functional>

#include <crc32.hpp>
#include <display.hpp>
#include <buffer.hpp>
#include "hostcx.hpp"

std::once_flag SSLCom::openssl_thread_setup_done;
std::once_flag SSLCom::certstore_setup_done;
SSLCertStore*  SSLCom::sslcom_certstore_;

int SSLCom::sslcom_ssl_extdata_index = -1;

int SSLCom::counter_ssl_connect = 0;
int SSLCom::counter_ssl_accept = 0;
unsigned int SSLCom::log_level = NON;

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


static struct CRYPTO_dynlock_value * dyn_create_function(const char *file,
                                                         int line)
{
    struct CRYPTO_dynlock_value *value;
 
//     value = (struct CRYPTO_dynlock_value *)malloc(sizeof(
//                                                   struct CRYPTO_dynlock_value));
    value = new CRYPTO_dynlock_value();
    
    if (!value)
        return NULL;
    MUTEX_SETUP(value->mutex);
    return value;
}
 
static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
                              const char *file, int line)
{
    if (mode & CRYPTO_LOCK)
        MUTEX_LOCK(l->mutex);
    else
        MUTEX_UNLOCK(l->mutex);
}
 
static void dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                                 const char *file, int line)
{
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



SSLCom::SSLCom() {
    sslcom_peer_hello_buffer.capacity(1500);
}


void SSLCom::static_init() {

    baseCom::static_init();

    DEBS__("SSL: Static INIT");

	if(false) {	
		// make compiler happy
		mutex_buf = NULL;
		locking_function(0,0,NULL,0);
		id_function();
	}

	// call openssl threads support - only once from all threads!
	std::call_once (SSLCom::openssl_thread_setup_done ,THREAD_setup);
    std::call_once (SSLCom::certstore_setup_done ,SSLCom::certstore_setup);
}


void SSLCom::init(baseHostCX* owner)  {
	
	TCPCom::init(owner);
}

const char* SSLCom::hr()  { 
    
    bool online = false;
    if(owner_cx() != nullptr) {
        online = owner_cx()->online_name;
    }
    
    if(hr_.size() > 0 && ! online) {
        return hr_.c_str();
    }
    
    if(owner_cx() != nullptr) {
        hr_ = owner_cx()->full_name('L'); 
        return hr_.c_str();
    }
    
    return nullptr;
}

void SSLCom::ssl_info_callback(const SSL* s, int where, int ret) {

    const char *name = "unknown_cx";
    
    SSLCom* com = static_cast<SSLCom*>(s->msg_callback_arg);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }
    
    const char *str;

    int w = where& ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT) str="SSL_connect";
    else if (w & SSL_ST_ACCEPT) str="SSL_accept";
    else str="undefined";

    if (where & SSL_CB_LOOP)
    {
        DEB__("[%s]: SSLCom::ssl_info_callback: %s:%s",name,str,SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT)
    {
        str=(where & SSL_CB_READ)?"read":"write";
        DIA__("[%s]: SSLCom::ssl_info_callback: SSL3 alert %s:%s:%s", name, str, SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT)
    {
        if (ret == 0) {
            DEB__("[%s]: SSLCom::ssl_info_callback: %s:failed in %s", name, str,SSL_state_string_long(s));
        }
        else if (ret < 0)  {
            DEB__("[%s]: SSLCom::ssl_info_callback %s:error in %s", name, str,SSL_state_string_long(s));
        }
    }
    
}

void SSLCom::ssl_msg_callback(int write_p, int version, int content_type, const void* buf, size_t len, SSL* ssl, void* arg)
{
    const char *msg_version;
    const char *msg_direction;
    const char *msg_content_type;
    
    const char *name = "unknown_cx";
    
    SSLCom* com = static_cast<SSLCom*>(arg);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }
    
    switch (version) {
        case SSL2_VERSION:
            msg_version = "ssl2";
            break;
        case SSL3_VERSION:
            msg_version = "ssl3";
            break;
        case TLS1_VERSION:
            msg_version = "tls1.0";
            break;
        case TLS1_1_VERSION:
            msg_version = "tls1.1";
            break;
        case TLS1_2_VERSION:
            msg_version = "tls1.2";
            break;
            
        default:
            msg_version = "unknown";
    }
    
    switch(content_type) {
        case 20:
            msg_content_type = "ChangeCipherSpec";
            break;
        case 21:
            msg_content_type = "Alert";
            break;
        case 22:
            msg_content_type = "Handshake";
            break;
        case 23:
            msg_content_type = "ApplicationData";
            break;
        
        default:
            msg_content_type = "Unknown";
    }
    
    if(write_p == 0) {
        msg_direction = "received";
    } else {
        msg_direction = "sent";
    }
    
    DEB__("[%s]: SSLCom::ssl_msg_callback: %s/%s has been %s",name,msg_version,msg_content_type,msg_direction);
    
    if(content_type == 21) {
        DEB__("[%s]: SSLCom::ssl_msg_callback: alert dump: %s",name,hex_dump((unsigned char*)buf,len).c_str());
        unsigned short code = ntohs(buffer::get_at<unsigned short>((unsigned char*)buf));
        if(com) {
            DIA__("[%s]: SSLCom::ssl_msg_callback: alert info: %s/%s[%u]",name,SSL_alert_type_string_long(code),SSL_alert_desc_string_long(code),code);
            if(code == 522) {
                // unexpected message
                DEB__("  [%s]: prof_accept_cnt %d, prof_connect_cnt %d, prof_peek_cnt %d, prof_read_cnt %d, prof_want_read_cnt %d, prof_want_write_cnt %d, prof_write_cnt %d",
                    name, com->prof_accept_cnt   , com->prof_connect_cnt   , com->prof_peek_cnt   , com->prof_read_cnt   , com->prof_want_read_cnt   , com->prof_want_write_cnt   , com->prof_write_cnt);
                DEB__("  [%s]: prof_accept_ok %d, prof_connect_ok %d",name, com->prof_accept_ok, com->prof_connect_ok);
            }
        }
    }
}



int SSLCom::ssl_client_vrfy_callback(int ok, X509_STORE_CTX *ctx) {
    
    X509 * err_cert = X509_STORE_CTX_get_current_cert(ctx);
    int err =   X509_STORE_CTX_get_error(ctx);
    int depth = X509_STORE_CTX_get_error_depth(ctx);
    int idx = SSL_get_ex_data_X509_STORE_CTX_idx();
    int ret = ok;
    
    DEB__("SSLCom::ssl_client_vrfy_callback: data index = %d, ok = %d, depth = %d",idx,ok,depth);

    SSL* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx()));
    void* data = SSL_get_ex_data(ssl, sslcom_ssl_extdata_index);
    const char *name = "unknown_cx";
    
    SSLCom* com = static_cast<SSLCom*>(data);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }    
    

    if (!ok) {
        if (err_cert) {
            DIA__("[%s]: SSLCom::ssl_client_vrfy_callback: '%s' issued by '%s'",name,SSLCertStore::print_cn(err_cert).c_str(),
                                                                                    SSLCertStore::print_issuer(err_cert).c_str());
        }
        else {
            DIA__("[%s]: SSLCom::ssl_client_vrfy_callback: no server certificate",name);
        }        
        DIA__("[%s]: SSLCom::ssl_client_vrfy_callback: %d:%s",name, err, X509_verify_cert_error_string(err));
    }
    
    switch (err)
    {
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        case X509_V_ERR_CERT_UNTRUSTED:
            //INF__("[%s]: SSLCom::ssl_client_vrfy_callback: issuer: %s", name, SSLCertStore::print_issuer(err_cert).c_str());
            if(com != nullptr) 
            if(com->opt_allow_unknown_issuer || com->opt_allow_self_signed_chain) {
                ret = 1;
            }
            
            break;
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            if(com != nullptr) 
            if(com->opt_allow_self_signed_cert) {
                ret = 1;
            }
            break;
            
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            DIA__("[%s]: SSLCom::ssl_client_vrfy_callback: not before: %s",name, SSLCertStore::print_not_before(err_cert).c_str());
            if(com != nullptr) 
            if(com->opt_allow_not_valid_cert) {
                ret = 1;
            }
            
            break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            DIA__("[%s]: SSLCom::ssl_client_vrfy_callback: not after: %s",name, SSLCertStore::print_not_after(err_cert).c_str());
            if(com != nullptr) 
            if(com->opt_allow_not_valid_cert) {
                ret = 1;
            }

            break;
        case X509_V_ERR_NO_EXPLICIT_POLICY:
            INF__("[%s]: SSLCom::ssl_client_vrfy_callback: no explicit policy",name);
            break;
    }
    if (err == X509_V_OK && ok == 2) {
        DIA__("[%s]: SSLCom::ssl_client_vrfy_callback: explicit policy", name);
    }
    
    
    DIA__("[%s]: SSLCom::ssl_client_vrfy_callback[%d]: returning %s (pre-verify %d)",name,depth,(ret > 0 ? "ok" : "failed" ),ok);
    if(ret <= 0) {
        NOT__("[%s]: target server ssl certificate check failed:%d: %s",name, err,X509_verify_cert_error_string(err));   
    }
    
    if(com != nullptr) {
      com->status_client_verify = err;
    }
    
    return ret;
}


long int SSLCom::log_if_error(unsigned int level, const char* prefix) {
    
    long err2 = ERR_get_error();
    do {
        if(err2 != 0) {
            LOGS___(level, string_format("%s: error code:%u:%s",prefix, err2,ERR_error_string(err2,nullptr)).c_str());
            err2 = ERR_get_error();
        }
    } while (err2 != 0);
    
    return err2;
}


long int SSLCom::log_if_error2(unsigned int level, const char* prefix) {
    
    long err2 = ERR_get_error();
    do {
        if(err2 != 0) {
            LOGS__(level, string_format("%s: error code:%u:%s",prefix, err2,ERR_error_string(err2,nullptr)).c_str());
            err2 = ERR_get_error();
        }
    } while (err2 != 0);
    
    return err2;
}

DH* SSLCom::ssl_dh_callback(SSL* s, int is_export, int key_length)  {
    void* data = SSL_get_ex_data(s, sslcom_ssl_extdata_index);
    const char *name = "unknown_cx";
    
    SSLCom* com = static_cast<SSLCom*>(data);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }
    INF__("[%s]: SSLCom::ssl_dh_callback: %d bits requested",name,key_length);
    switch(key_length) {
        case 512:
            //return get_dh512();
        case 768:
            //return get_dh768();
        case 1024:
            return get_dh1024();
        case 1536:
            return get_dh1536();
        case 2048:
            return get_dh2048();
            
            
        default:
            return get_dh2048();
    }
    
    return nullptr;
}

EC_KEY* SSLCom::ssl_ecdh_callback(SSL* s, int is_export, int key_length) {
    void* data = SSL_get_ex_data(s, sslcom_ssl_extdata_index);
    const char *name = "unknown_cx";
    
    SSLCom* com = static_cast<SSLCom*>(data);
    if(com != nullptr) {
        const char* n = com->hr();
        if(n != nullptr) {
            name = n;
        }
    }    
    INF__("[%s]: SSLCom::ssl_ecdh_callback: %d bits requested",name,key_length);
    return nullptr;
}


void SSLCom::init_ssl_callbacks() {
    SSL_set_msg_callback(sslcom_ssl,ssl_msg_callback);
    SSL_set_msg_callback_arg(sslcom_ssl,(void*)this);
    SSL_set_info_callback(sslcom_ssl,ssl_info_callback);
    
    if(opt_pfs) {
        SSL_set_tmp_dh_callback(sslcom_ssl,ssl_dh_callback);
        SSL_set_tmp_ecdh_callback(sslcom_ssl,ssl_ecdh_callback);
    }
    
    // add this pointer to ssl external data
    if(sslcom_ssl_extdata_index < 0) {
        sslcom_ssl_extdata_index = SSL_get_ex_new_index(0, (void*) "sslcom object", nullptr, nullptr, nullptr);
    }
    SSL_set_ex_data(sslcom_ssl,sslcom_ssl_extdata_index,(void*)this);    
    
    if(! is_server()) {
        SSL_set_verify(sslcom_ssl,SSL_VERIFY_PEER,&ssl_client_vrfy_callback);
    }
    
}


void SSLCom::init_client() {

    if(sslcom_ssl) {
        DEBS___("SSLCom::init_client: freeing old sslcom_ssl");
        SSL_free(sslcom_ssl);
    }
    
    
    sslcom_ctx = certstore()->def_cl_ctx;
    sslcom_ssl = SSL_new(sslcom_ctx);
    
    if(!sslcom_ssl) {
        ERRS___("Client: Error creating SSL context!");
        log_if_error(ERR,"SSLCom::init_client");
    }
    
    SSL_set_session(sslcom_ssl, NULL);
    SSL_set_mode(sslcom_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);


    init_ssl_callbacks();
}


void SSLCom::init_server() {
	
    if(sslcom_ssl) {
        DEBS___("SSLCom::init_server: freeing old sslcom_ssl");
        SSL_free(sslcom_ssl);
    }

    sslcom_ctx = certstore()->def_sr_ctx;
	sslcom_ssl = SSL_new(sslcom_ctx);
    
    if(opt_pfs) {
        sslcom_ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); 
        if(sslcom_ecdh != nullptr) {
            // this actually disables ecdh callback
            SSL_set_tmp_ecdh(sslcom_ssl,sslcom_ecdh);
        }
    }
    
    if (sslcom_pref_cert && sslcom_pref_key) {
        DEB__("SSLCom::init_server[%x]: loading preferred key/cert",this);
        SSL_use_PrivateKey(sslcom_ssl,sslcom_pref_key);
        SSL_use_certificate(sslcom_ssl,sslcom_pref_cert);
        
    }
    
    SSL_set_session(sslcom_ssl, NULL);
    SSL_set_mode(sslcom_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	
	SSL_set_fd (sslcom_ssl, sslcom_fd);
	
    is_server(true);

    init_ssl_callbacks();
}

bool SSLCom::check_cert (const char* host) {
    X509 *peer;
    char peer_CN[256];

    if ( !is_server() && SSL_get_verify_result ( sslcom_ssl ) !=X509_V_OK ) {
        DIAS___( "check_cert: ssl client: target server's certificate cannot be verified!" );
    }

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name*/
    peer=SSL_get_peer_certificate ( sslcom_ssl );
	
	if(peer == NULL) {
		ERRS___("check_cert: unable to retrieve peer certificate");
		
		// cannot proceed, next checks require peer X509 data
		return false;
	};
	
    X509_NAME* x509_name = X509_get_subject_name(peer);
    X509_NAME_get_text_by_NID(x509_name,NID_commonName, peer_CN, 256);
// 	X509_NAME_oneline(X509_get_subject_name(peer),peer_CERT,1024);
//	DIA___("Peer certificate:\n%s",peer_CERT);
	
	DIA___("peer CN: %s",peer_CN);
	if(host != NULL) {
		DIA___("peer host: %s",host);
		
		if ( strcasecmp ( peer_CN,host ) ) {
		DIAS___( "Common name doesn't match host name" );
		}
	}
	
	X509_free(peer);
//     X509_NAME_free(x509_name);
    
	// finally, SSL is up, set status flag
	sslcom_status(true);
	
	return true;
}


/* OK set  */
bool SSLCom::readable(int s) { 
    // 	bool r = ( sslcom_write_blocked_on_read  || !sslcom_read_blocked_on_write || sslcom_waiting ); 
    bool r = !sslcom_read_blocked_on_write;
    sslcom_read_blocked_on_write = false;

    DUM___("SSLCom::readable[%d]: sslcom_read_blocked_on_write: %d",s,sslcom_read_blocked_on_write);
    DUM___("SSLCom::readable[%d]: sslcom_write_blocked_on_read: %d",s,sslcom_write_blocked_on_read);  
    
	if (r) {
		DUM___("SSLCom::readable[%d]: %d",s,r);
	} else {
		DEB___("SSLCom::readable[%d]: %d",s,r);
	}
	
	return r;
};
bool SSLCom::writable(int s) { 
    // 	bool r  = ( sslcom_read_blocked_on_write ||  !sslcom_write_blocked_on_read ||  sslcom_waiting ); 	
	
    bool r = !sslcom_write_blocked_on_read;
    sslcom_write_blocked_on_read = false;
    
	DUM___("SSLCom::writable[%d]: sslcom_read_blocked_on_write: %d",s,sslcom_read_blocked_on_write);
    DUM___("SSLCom::writable[%d]: sslcom_write_blocked_on_read: %d",s,sslcom_write_blocked_on_read);  
	
	if (r) {
		DUM___("SSLCom::writable[%d]: %d",s,r);
	} else {
		DEB___("SSLCom::writable[%d]: %d",s,r);
	}
	
	return r;
};	
/**/

/* TESTING set
bool SSLCom::readable(int s) { 
	return ((FD_ISSET(s,&read_socketSet) && sslcom_write_blocked_on_read) ||
        (!sslcom_read_blocked_on_write && FD_ISSET(s,&write_socketSet)) || sslcom_waiting); 
};
bool SSLCom::writable(int s) { 
	return (FD_ISSET(s,&write_socketSet) || (sslcom_read_blocked_on_write )); 
};	
 */


void SSLCom::accept_socket ( int sockfd )  {

	DIA___("SSLCom::accept_socket[%d]: attempt %d",sockfd,prof_accept_cnt);
	
	TCPCom::accept_socket(sockfd);
	
    upgrade_server_socket(sockfd);
    if(opt_bypass) {
	prof_accept_bypass_cnt++;
	return;
    }
    
    
    ERR_clear_error();
    int r = SSL_accept (sslcom_ssl);
    if (r > 0) {
        DIA___("SSLCom::accept_socket[%d]: success at 1st attempt.",sockfd);
        prof_accept_ok++;
        sslcom_waiting = false;
        
        // reread socket
        forced_read(true);
        forced_write(true);

    } else {
        DIA___("SSLCom::accept_socket[%d]: ret %d, need to call later.",sockfd,r);
    }
    prof_accept_cnt++;
}

void SSLCom::delay_socket(int sockfd) {
    // we need to know even delayed socket
    sslcom_fd = sockfd;
}


int SSLCom::upgrade_server_socket(int sockfd) {

    sslcom_fd = sockfd;
    sslcom_waiting = true;
    unblock(sslcom_fd);

    if(opt_bypass) {
	DIA___("SSLCom::upgrade_server_socket[%d]: bypassed",sockfd);
	return sockfd;
    }
    
    init_server();

//     sslcom_sbio = BIO_new_socket(sockfd,BIO_NOCLOSE);
//     if (sslcom_sbio == NULL) {
//         ERR___("BIO allocation failed for socket %d",sockfd)
//     }
//     
//     SSL_set_bio(sslcom_ssl,sslcom_sbio,sslcom_sbio);

    upgraded(true);
    return sockfd;
}

// return -1 on unrecoverable and we should stop 
// return 0 when still waiting
// return > 0 when not waiting anymore 
int SSLCom::waiting() {

	const char* op_accept = "accept";
	const char* op_connect = "connect";
	const char* op_unknown = "?unknown?";
	
	const char* op = op_unknown;
	
	if (sslcom_ssl == NULL and ! auto_upgrade()) {
		WARS___("SSLCom::ssl_waiting: sslcom_ssl = NULL");
        return -1;
	}
	
	int r = 0;
	
	if (!is_server() ) {

        // if we still wait for client hello, try to fetch and enforce (first attempt not successful on connect())
        if(!sslcom_peer_hello_received()) {
            
            if(! waiting_peer_hello()) {
                // nope, still nothing. Wait further
                return 0;
            }
            
            // if we got here, upgrade client socket prior SSL_connect! Keep it here, it has to be just once!
            if(auto_upgrade()) {
                DIA___("SSLCom::waiting[%d]: executing client auto upgrade",sslcom_fd);
                if(owner_cx() != nullptr && sslcom_fd == 0) {
                    sslcom_fd = owner_cx()->socket();
                    DIA___("SSLCom::waiting[%d]: socket 0 has been auto-upgraded to owner's socket",sslcom_fd);
                }
                upgrade_client_socket(sslcom_fd);
            }
        } 
        
        // we have client hello
        if(sslcom_peer_hello_received()){

            DEBS___("SSLCom::waiting: before SSL_connect");
            
            ERR_clear_error();
            r = SSL_connect(sslcom_ssl);
            prof_connect_cnt++;
            
            //debug counter
            SSLCom::counter_ssl_connect++;
        }
		op = op_connect;
	} 
	else if(is_server()) {
        
        if(auto_upgrade() && !upgraded()) {
            DIAS___("SSLCom::waiting: server auto upgrade");
            upgrade_server_socket(sslcom_fd);
        }
        
        ERR_clear_error();
		r = SSL_accept(sslcom_ssl);
        prof_accept_cnt++;
        
        SSLCom::counter_ssl_accept++;
        
		op = op_accept;
	}
		

	if (r < 0) {
		int err = SSL_get_error(sslcom_ssl,r);
		if (err == SSL_ERROR_WANT_READ) {
			DUM___("SSLCom::waiting: SSL_%s: want read",op);
			
 			sslcom_waiting = true;
            prof_want_read_cnt++;
//             forced_read(true);
// 			sslcom_waiting_read = true;
 			return 0;
		}
		else if (err == SSL_ERROR_WANT_WRITE) {
			DUM___("SSLCom::waiting: SSL_%s: want write",op);
			
 			sslcom_waiting = true;
            prof_want_write_cnt++;
//             forced_write(true);
// 			    sslcom_waiting_write = true;
 			return 0;
		}
		else {
            DIA___("SSLCom::waiting: SSL_%s: error: %d",op,err);
            
            long err2 = ERR_get_error();
            do {
                if(err2 != 0 || LEV_(DEB)) {
                    DIA___("SSLCom::waiting:   error code: %s",ERR_error_string(err2,nullptr));
                    err2 = ERR_get_error();
                }
            } while (err2 != 0);
            
            
 			sslcom_waiting = true;
 			return -1;
		}
 
		
// 	} else if (r < -1) {
// 		DIA___("SSLCom::waiting: SSL failed: %s, ret %d",op,r);
//         
//         long err2 = ERR_get_error();
//         DIA___("SSLCom::waiting:   error code: %s",ERR_error_string(err2,nullptr));
// 		
// 		//unclean shutdown
// 		sslcom_waiting = false;
// 		SSL_shutdown(sslcom_ssl);
// 		return -1;
		
	} else if (r == 0) {
		DIA___("SSLCom::waiting: SSL failed: %s, ret %d",op ,r);

        long err2 = ERR_get_error();
        DIA___("SSLCom::waiting:   error code: %s",ERR_error_string(err2,nullptr));

        // shutdown OK, but connection failed
		sslcom_waiting = false;		
		return -1;
	}
	
	if(!is_server()) {
        prof_connect_ok++;
    } else {
        prof_accept_ok++;
    }
	
	DEB___("SSLCom::waiting: operation succeeded: %s", op);
	sslcom_waiting = false;	

	if(!is_server()) {
		check_cert(ssl_waiting_host);
	}
	
	return r;
	
}

bool SSLCom::waiting_peer_hello()
{
    
    DUMS___("SSLCom::waiting_peer_hello: start");
    
    if(sslcom_peer_hello_received_) {
        DEBS___("SSLCom::waiting_peer_hello: already called, returning true");
        return true;
    }
    
    DUMS___("SSLCom::waiting_peer_hello: called");
    if(peer()) {
        SSLCom *p = static_cast<SSLCom*>(peer());
        if(p != nullptr) {
            if(p->sslcom_fd > 0) {
                DUMS___("SSLCom::waiting_peer_hello: peek max %d bytes from peer socket %d",sslcom_peer_hello_buffer.capacity(),p->sslcom_fd);
                
                int red = ::recv(p->sslcom_fd,sslcom_peer_hello_buffer.data(),sslcom_peer_hello_buffer.capacity(),MSG_PEEK);
                if (red > 0) {
                    sslcom_peer_hello_buffer.size(red);
                    
                    DIA___("SSLCom::waiting_peer_hello: %d bytes in buffer for hello analysis",red);
                    DUM___("SSLCom::waiting_peer_hello: ClientHello data:\n%s",hex_dump(sslcom_peer_hello_buffer.data(),sslcom_peer_hello_buffer.size()).c_str());
                    
                    if (! parse_peer_hello()) {
                        DIAS___("SSLCom::waiting_peer_hello: analysis failed");
                        DIA___("SSLCom::waiting_peer_hello: failed ClientHello data:\n%s",hex_dump(sslcom_peer_hello_buffer.data(),sslcom_peer_hello_buffer.size()).c_str());
                        return false;
                    }
                    sslcom_peer_hello_received_ = true;
                    
                    if(sslcom_peer_hello_sni_.size() > 0) {
                        std::string subj = certstore()->find_subject_by_fqdn(sslcom_peer_hello_sni_);
                        if(subj.size() > 0) {
                            DIA___("SSLCom::waiting_peer_hello: peer's SNI found in subject cache: '%s'",subj.c_str());
                            if(! enforce_peer_cert_from_cache(subj)) {
                                DIAS___("SSLCom::waiting_peer_hello: fallback to slow-path");
                            }
                        } else {
                            DIAS___("Peer's SNI NOT found in certstore, no shortcuts possible.");
                        } 
                    }
                    
                } else {
                    DUM___("SSLCom::waiting_peer_hello: peek returns %d, readbuf=%d",red,owner_cx()->readbuf()->size());
                    DUM___("SSLCom::waiting_peer_hello: peek errno: %s",string_error().c_str());
                }
                
            } else {
                DIAS___("SSLCom::waiting_peer_hello: SSLCom peer doesn't have sslcom_fd set");
            }
        } else {
            DIAS___("SSLCom::waiting_peer_hello: peer not SSLCom type");
        }
    } else {
        DIAS___("SSLCom::waiting_peer_hello: no peers");
    }
    
    return sslcom_peer_hello_received_;
}


bool SSLCom::enforce_peer_cert_from_cache(std::string & subj) {
    if(peer() != nullptr) {
        
        if(peer()->owner_cx() != nullptr) {
            DIAS___("SSLCom::enforce_peer_cert_from_cache: about to force peer's side to use cached certificate");
            
            X509_PAIR* parek = certstore()->find(subj);
            if (parek != nullptr) {
                DIA___("Found cached certificate %s based on fqdn search.",subj.c_str());
                SSLCom* p = dynamic_cast<SSLCom*>(peer());
                if(p != nullptr) {
                    
                    if(p->sslcom_waiting) {
                        p->sslcom_pref_cert = parek->second;
                        p->sslcom_pref_key = parek->first;
                        //p->init_server(); this will be done automatically, peer was paused
                        p->owner_cx()->paused(false);
                        DIAS___("SSLCom::enforce_peer_cert_from_cache: peer certs replaced by SNI lookup, peer was unpaused.");
                        sslcom_peer_sni_shortcut = true;
                        
                        return true;
                    } else {
                        DIAS_("SSLCom::enforce_peer_cert_from_cache: cannot modify non-waiting peer!");
                    }
                } else {
                    DIAS___("SSLCom::enforce_peer_cert_from_cache: failed to update peer:  it's not SSLCom* type!");
                }
            } else {
                DIAS___("SSLCom::enforce_peer_cert_from_cache: failed to update initiator with cached certificate: certificate was not found.!");
            }
        }
    }    
    
    return false;
}


bool SSLCom::parse_peer_hello() {

    bool ret = false;
    
    uint8_t content_type = 0;
    
    try {

    buffer& b = sslcom_peer_hello_buffer;        
    if(b.size() >= 34) {

        buffer session_id = buffer();
        unsigned int curpos = 0;
        
        unsigned char message_type = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char);
        unsigned char version_maj = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char);
        unsigned char version_min = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char);
        
        unsigned short message_length = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
        
        
        DIA___("SSLCom::parse_peer_hello: buffer size %d, received message type %d, version %d.%d, length %d",b.size(),message_type,version_maj, version_min, message_length);
        if(b.size() != (unsigned int)message_length + 5) {
            DIAS___("SSLCom::parse_peer_hello: incomplete message received");
            return false;
        }
        
        if(message_type == 22) {
            
            unsigned char handshake_type = b.get_at<unsigned char>(curpos); curpos+=(sizeof(unsigned char) + 1); //@6 (there is padding 0x00, or length is 24bit :-O)
            unsigned short handshake_length = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short); //@9
            unsigned char handshake_version_maj = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char); //@10
            unsigned char handshake_version_min = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char); //@11
            unsigned int  handshake_unixtime = ntohl(b.get_at<unsigned char>(curpos)); curpos+=sizeof(unsigned int); //@15
            
            curpos += 28; // skip random 24B bytes
            
            unsigned char session_id_length = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char);
            
            // we already know it's handshake, it's ok to return true
            if(handshake_type == 1) {
                DIA___("SSLCom::parse_peer_hello: handshake (type %u), version %u.%u, length %u",handshake_type,handshake_version_maj,handshake_version_min,handshake_length);
                ret = true;
            }
            
            if(session_id_length > 0) {
                session_id = b.view(curpos,session_id_length); curpos+=session_id_length;
                DEB___("SSLCom::parse_peer_hello: session_id (length %d):\n%s",session_id_length, hex_dump(session_id.data(),session_id.size()).c_str());
            } else {
                DEBS___("SSLCom::parse_peer_hello: no session_id found.");
            }
            
            unsigned short ciphers_length = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
            curpos += ciphers_length; //skip ciphers
            unsigned char compression_length = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char);
            curpos += compression_length; // skip compression methods

            DEB___("SSLCom::parse_peer_hello: ciphers length %d, compression length %d",ciphers_length,compression_length);
            
            /* extension section */
            unsigned short extensions_length = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
            DEB___("SSLCom::parse_peer_hello: extensions payload length %d",extensions_length);
            
            if(extensions_length > 0) {

                // minimal extension size is 5 (2 for ID, 2 for len)
                while(curpos + 4 < b.size()) {
                    curpos += parse_peer_hello_extensions(b,curpos);
                }
            }
        }
    } else {
        DIA___("SSLCom::parse_peer_hello: only %d bytes in peek:\n%s",b.size(),hex_dump(b.data(),b.size()).c_str());
    }
    
    
    DIA___("SSLCom::parse_peer_hello: return status %s",ret ? "true" : "false");

    
    }
    catch (std::out_of_range e) {
        DIAS___(string_format("SSLCom::parse_peer_hello: failed to parse hello: %s",e.what()).c_str());
    }
    
    return ret;    
}

unsigned short SSLCom::parse_peer_hello_extensions(buffer& b, unsigned int curpos) {

    unsigned short ext_id = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
    unsigned short ext_length = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
    
    DEB___("SSLCom::parse_peer_hello_extensions: extension id 0x%x, length %d", ext_id, ext_length);

    switch(ext_id) {
        
        /* server name*/
        case 0: 
            unsigned short sn_list_length = htons(b.get_at<unsigned short>(curpos)); curpos+= sizeof(unsigned short);
            unsigned  char sn_type = b.get_at<unsigned char>(curpos); curpos+= sizeof(unsigned char);
            
            /* type is hostname*/
            if(sn_type == 0) {
                unsigned short sn_hostname_length = htons(b.get_at<unsigned short>(curpos)); curpos+= sizeof(unsigned short);
                std::string s;
                s.append((const char*)b.data()+curpos,(size_t)sn_hostname_length);
                
                DIA___("SSLCom::parse_peer_hello_extensions:    SNI hostname: %s",s.c_str());
                
                sslcom_peer_hello_sni_ = s;
                //SSL_set_tlsext_host_name(sslcom_ssl,s.c_str());
            }
            
            break;
    }
    
    return ext_length + 4;  // +4 for ext_id and ext_length
}



#pragma GCC diagnostic ignored "-Wpointer-arith"
#pragma GCC diagnostic push

int SSLCom::read ( int __fd, void* __buf, size_t __n, int __flags )  {
	
	int total_r = 0;
    int rounds = 0;

        if(opt_bypass) {
	    return TCPCom::read(__fd,__buf,__n,__flags);
	}
	
	// non-blocking socket can be still opening 
	if( sslcom_waiting ) {
        DUM___("SSLCom::read[%d]: still waiting for handshake to complete.",__fd);
		int c = waiting();

        if (c == 0) {
            DUM___("SSLCom:: read[%d]: ssl_waiting() returned %d: still waiting",__fd,c);
            return -1;
        } else 
        if (c < 0) {
            DIA___("SSLCom:: read[%d]: ssl_waiting() returned %d: unrecoverable!",__fd,c);
            return 0;
        }
        
        DIA___("SSLCom::read[%d]: handshake finished, continue with %s from socket",__fd, __flags & MSG_PEEK ? "peek" : "read");
        // if we were waiting, force next round of read
        forced_read(true);
    }   
	
	// if we are peeking, just do it and return, no magic done is here
	if ((__flags & MSG_PEEK) != 0) {
        DUM___("SSLCom::read[%d]: about to peek  max %4d bytes",__fd,__n);        
        int peek_r = SSL_peek(sslcom_ssl,__buf,__n);
        prof_peek_cnt++;
        
        if(peek_r > 0) {
            DIA___("SSLCom::read[%d]: peek returned %d",__fd, peek_r);
        } else {
            DUM___("SSLCom::read[%d]: peek returned %d",__fd, peek_r);
        } 
        
        return peek_r;
    }
	
    do {
		
		if(total_r >= (int)__n) {
			DEB___("SSLCom::read[%d]: reached buffer capacity of %4d bytes, forcing new read",__fd,__n);
            
            // this is tricky one :) 
            // I have spent quite couple of hours of troubleshooting this:
            // ... 
            // We have to break here, since write buffer is full
            // BUT 
            // openssl already has it internally 
            // => select won't return this socket as in read_set == no reads anymore !!!
            // => we have to have mechanism which will enforce read in the next round 
			forced_read(true);
            break;
		}
		
//         sslcom_read_blocked_on_write=0;
//         sslcom_read_blocked=0;

        EXT___("SSLCom::read[%d]: about to read  max %4d bytes",__fd,__n);
        
        ERR_clear_error();
        int r = SSL_read (sslcom_ssl,__buf+total_r,__n-total_r);
        prof_read_cnt++;
// 		if (r > 0) return r;

		if(r == 0) {
			DEBS___("SSLCom::read: SSL_read returned 0");
		}
		
		int err = SSL_get_error ( sslcom_ssl,r);
        switch ( err ) {
			case SSL_ERROR_NONE:
				/* Note: this call could block, which blocks the
				entire application. It's arguable this is the
				right behavior since this is essentially a terminal
				client. However, in some other applications you
				would have to prevent this condition */
				// fwrite ( s2c,1,r,stdout );
				
				DIA___("SSLCom::read [%d]: %4d bytes read:%d from ssl socket %s, %X",__fd,r,rounds,(r == (signed int)__n) ? "(max)" : "",
                                debug_log_data_crc ? socle_crc32(0,__buf,r) : 0
                );
                
                if(r > 0)
				total_r += r;
				
				sslcom_read_blocked_on_write=0;
				sslcom_read_blocked=0;				
				break;
				
			case SSL_ERROR_ZERO_RETURN:
				DEB___("SSLCom::read[%d]: zero returned",__fd);
				SSL_shutdown (sslcom_ssl);
				return r;
				
			case SSL_ERROR_WANT_READ:
				if(r == -1){
					DEB___("SSLCom::read[%d]: want read: err=%d,read_now=%4d,total=%4d",__fd,err,r,total_r);
				}
				else {
					DEB___("SSLCom::read[%d]: want read: err=%d,read_now=%4d,total=%4d",__fd,err,r,total_r);
				}
				sslcom_read_blocked=1;
                forced_read(true);
                
                if(total_r > 0) return total_r;
				return r;

				/* We get a WANT_WRITE if we're
				trying to rehandshake and we block on
				a write during that rehandshake.

				We need to wait on the socket to be
				writeable but reinitiate the read
				when it is */
				
			case SSL_ERROR_WANT_CONNECT:
				DIA___("SSLCom::read[%d]: want connect",__fd);
                
                if(total_r > 0) return total_r;
				return r;

			case SSL_ERROR_WANT_ACCEPT:
				DIA___("SSLCom::read[%d]: want accept",__fd);

                if(total_r > 0) return total_r;              
				return r;
				
				
			case SSL_ERROR_WANT_WRITE:
				DEB___("SSLCom::read[%d]: want write, last read retured %d, total read %4d",__fd,r,total_r);
				sslcom_read_blocked_on_write=1;
                
                //forced_write(true);  // we can opportinistically enforce write operation regardless of select result
                forced_read_on_write(true);
                
				if(total_r > 0) return total_r;
				return r;
			
			case SSL_ERROR_WANT_X509_LOOKUP:
				DIA___("SSLCom::read[%d]: want x509 lookup",__fd);
				if(total_r > 0) return total_r;
				return r;
				
			case SSL_ERROR_SYSCALL:
				DIA___("SSLCom::read[%d]: syscall errorq",__fd);
				if(total_r > 0) return total_r;
				return r;
				
			default:
				if (r != -1 && err != 1) {
					DIA___("SSLCom::read[%d] problem: %d, read returned %4d",__fd,err,r);
				}
	// 			SSL_shutdown (sslcom_ssl);
				if(total_r > 0) return total_r;
				return r;
        }

        /* We need a check for read_blocked here because
           SSL_pending() doesn't work properly during the
           handshake. This check prevents a busy-wait
           loop around SSL_read() */
		rounds++;
		
    //} while ( SSL_pending ( sslcom_ssl ) && !sslcom_read_blocked );
    } while ( SSL_pending ( sslcom_ssl ) && !sslcom_read_blocked);

	DIA___("SSLCom::read: total %4d bytes read",total_r);

	if(total_r == 0) {
		DIAS___("SSLCom::read: logic error, total_r == 0");
	}
	
	return total_r;
}

int SSLCom::write ( int __fd, const void* __buf, size_t __n, int __flags )  {

    if(__n == 0) {
        EXT___("SSLCom::write[%d]: called: about to write %d bytes",__fd,__n);    
    } else {
        DEB___("SSLCom::write[%d]: called: about to write %d bytes",__fd,__n);	
    }
    
    
    if(opt_bypass) {
	return TCPCom::write(__fd,__buf,__n,__flags);
    }
	
	//this one will be much trickier than just single call of SSL_read
	// return SSL_write(sslcom_ssl, __buf, __n);

// 	// non-blocking socket can be still opening 
	if( sslcom_waiting ) {
        DUM___("SSLCom::write[%d]: still waiting for handshake to complete.",__fd);
        
		int c = waiting();
		if (c == 0) {
			DUM___("SSLCom::write[%d]: ssl_waiting() returned %d: still waiting",__fd,c);
			return 0;
		} else 
        if (c < 0) {
            DIA___("SSLCom::write[%d]: ssl_waiting() returned %d: unrecoverable!",__fd,c);
            return -1;
        }
        DIA___("SSLCom::write[%d]: handshake finished, continue with writing to socket",__fd);
        // if we were waiting, force next round of write
        forced_write(true);
	}	
	
    sslcom_write_blocked_on_read=0;
    int normalized__n = 20480;
    void *ptr = (void*)__buf;

    if(__n == 0) {
        EXT___("SSLCom::write[%d]: attempt to send %d bytes",__fd,__n);
    } else {
        DEB___("SSLCom::write[%d]: attempt to send %d bytes",__fd,__n);
    }
    if ( __n < 20480) {
        normalized__n = __n;
    }

    if (__n <= 0 ) {
         return 0;
    }
    
    again:

    /* Try to write */
    ERR_clear_error();
    int r = SSL_write (sslcom_ssl,ptr,normalized__n);
    
    if(r >= normalized__n) {
        forced_write(true);
    }
    
    prof_write_cnt++;

// 	if (r > 0) return r;
	
	int err = SSL_get_error ( sslcom_ssl,r );
	bool is_problem = true;
	
    switch ( err ) {

		/* We wrote something*/
		case SSL_ERROR_NONE:
			DIA___("SSLCom::write[%d]: %4d bytes written to the ssl socket %s, %X",__fd,r, r != (signed int)__n ? "(incomplete)" : "",
                            debug_log_data_crc ? socle_crc32(0,__buf,r) : 0
            );
			is_problem = false;
            
            sslcom_write_blocked_on_read = 0;
            
			break;
			
		/* We would have blocked */
		case SSL_ERROR_WANT_WRITE:
			DIA___("SSLCom::write[%d]: want write: %d (written %4d)",__fd,err,r);	

			if (r > 0) {
				normalized__n = normalized__n - r;
				ptr += r;
			} else {
				DUM___("SSLCom::write[%d]: want write: repeating last operation",__fd);	
			}

			goto again;
			break;

		/* We get a WANT_READ if we're
			trying to rehandshake and we block on
			write during the current connection.

			We need to wait on the socket to be readable
			but reinitiate our write when it is */
		case SSL_ERROR_WANT_READ:
			DIA___("SSLCom::write[%d]: want read: %d (written %4d)",__fd,err,r);	
			sslcom_write_blocked_on_read=1;
//             forced_read(true);
            
            forced_write_on_read(true);
			break;

			/* Some other error */
		default:
			DEB___("SSLCom::write[%d]: problem: %d",__fd,err);


	}
	
	if (is_problem) {
		return 0;
	}
	
	return r;
};

#pragma GCC diagnostic pop

void SSLCom::cleanup()  {

    DIA__("  prof_accept %d, prof_connect %d, prof_peek %d, prof_read %d, prof_want_read %d, prof_want_write %d, prof_write %d",
        prof_accept_cnt   , prof_connect_cnt   , prof_peek_cnt   , prof_read_cnt   , prof_want_read_cnt   , prof_want_write_cnt   , prof_write_cnt);
    DIA__("   prof_accept_ok %d, prof_connect_ok %d",prof_accept_ok, prof_connect_ok);
    
//     if(sslcom_sbio) {
//         BIO_free(sslcom_sbio); // produces Invalid read of size 8: at 0x539D840: BIO_free (in /usr/lib/x86_64-linux-gnu/libcrypto.so.1.0.0)
//         sslcom_sbio = nullptr;
//     }

    if (!sslcom_waiting) {
        int shit = SSL_shutdown(sslcom_ssl);  //_sh_utdown _it_
        if (shit == 0) SSL_shutdown(sslcom_ssl);
    }
    
	if(sslcom_ssl) 	{
        SSL_free (sslcom_ssl);
        sslcom_ssl = nullptr;
    }
    
// 	if (sslcom_ctx) {
//         SSL_CTX_free(sslcom_ctx);
//         sslcom_ctx = nullptr;
//     }
    
    TCPCom::cleanup();    
} 


int SSLCom::upgrade_client_socket(int sock) {

    sslcom_fd = sock;
    
    bool ch = waiting_peer_hello();
    
    if(ch) {

	if(opt_bypass) {
	    DIA___("SSLCom::upgrade_client_socket[%d]: bypassed",sock);
	    return sock;
	}
      
      
        init_client();
        
        if(sslcom_ssl == NULL) {
            ERR___("SSLCom::upgrade_client_socket[%d]: failed to create SSL structure!",sock);
        }
    //  SSL_set_fd (sslcom_ssl, sock);
        
        if(sslcom_peer_hello_sni_.size() > 0) {
            DIA_("SSLCom::upgrade_client_socket[%d]: set sni extension to: %s",sock, sslcom_peer_hello_sni_.c_str());
            SSL_set_tlsext_host_name(sslcom_ssl, sslcom_peer_hello_sni_.c_str());
        }
        
        sslcom_sbio = BIO_new_socket(sock,BIO_NOCLOSE);
        if (sslcom_sbio == NULL) {
            ERR___("SSLCom::upgrade_client_socket[%d]: BIO allocation failed! ",sock)
        }
        
        SSL_set_bio(sslcom_ssl,sslcom_sbio,sslcom_sbio);          
        
        ERR_clear_error();
        int r = SSL_connect(sslcom_ssl);  
        prof_connect_cnt++;
        
        if(r <= 0 && is_blocking(sock)) {
            ERR___("SSL connect error on socket %d",sock);
            close(sock);
            return -1;
        }
        else if (r <= 0) {
            /* non-blocking may return -1 */
            
            if (r == -1) {
                int err = SSL_get_error(sslcom_ssl,r);
                if (err == SSL_ERROR_WANT_READ) {
                    DIA___("upgrade_client_socket[%d]: SSL_connect: pending on want_write",sock);
                }
                else 
                if(err == SSL_ERROR_WANT_READ) {
                    DIA___("upgrade_client_socket[%d]: SSL_connect: pending on want_read",sock);
                    
                }
                sslcom_waiting = true;
                return sock;
            }
            return sock;    
        }
        
        prof_connect_ok++;
        
        DEB___("SSLCom::upgrade_client_socket[%d]: connection succeeded",sock);  
        sslcom_waiting = false;
        
        //ssl_waiting_host = (char*)host;    
        check_cert(nullptr);
        
        forced_read(true);
        forced_write(true);
        
        upgraded(true);
    }
    
   
    return sock;
    

}


int SSLCom::connect ( const char* host, const char* port, bool blocking )  {
	int sock = TCPCom::connect( host, port, blocking );
	
// 	if (SSL_CTX_set_session_id_context(sslcom_ctx,
// 								   (const unsigned char*)sslcom_server_session_id_context,
// 									strlen(sslcom_server_session_id_context)) == 0) {
// 
// 		ERRS___("Setting session ID context failed!");
// 	}
   
    DIA___("SSLCom::connect[%d]: tcp connected",sock);
    sock = upgrade_client_socket(sock);

    if(upgraded()) {
        DIA___("SSLCom::connect[%d]: socket upgraded at 1st attempt!",sock);
    }
    
    return sock;
}

SSL_CTX* SSLCom::client_ctx_setup(EVP_PKEY* priv, X509* cert, const char* ciphers) {
//SSL_CTX* SSLCom::client_ctx_setup() {
  
    // SSLv3 -> latest TLS
    const SSL_METHOD *method = SSLv23_client_method();

    SSL_CTX* ctx = SSL_CTX_new (method);  

    if (!ctx) {
        ERRS__("SSLCom::client_ctx_setup: Error creating SSL context!");
        //log_if_error(ERR,"SSLCom::init_client");
        exit(2);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!aNULL:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);
    SSL_CTX_set_options(ctx,SSL_OP_NO_TICKET+SSL_OP_NO_SSLv3);


    DIAS__("SSLCom::client_ctx_setup: loading default key/cert");
    priv == nullptr ? SSL_CTX_use_PrivateKey(ctx,certstore()->def_cl_key) : SSL_CTX_use_PrivateKey(ctx,priv);
    cert == nullptr ? SSL_CTX_use_certificate(ctx,certstore()->def_cl_cert) : SSL_CTX_use_certificate(ctx,cert);

    if (!SSL_CTX_check_private_key(ctx)) {
        ERRS__("SSLCom::client_ctx_setup: Private key does not match the certificate public key\n");
        exit(5);
    }   
    
    return ctx;
}

SSL_CTX* SSLCom::server_ctx_setup(EVP_PKEY* priv, X509* cert, const char* ciphers) {
//SSL_CTX* SSLCom::server_ctx_setup() {
    
    // SSLv3 -> latest TLS
    const SSL_METHOD *method = SSLv23_server_method();
    SSL_CTX* ctx = SSL_CTX_new (method);  
    
    if (!ctx) {
        ERRS__("SSLCom::server_ctx_setup: Error creating SSL context!");
        exit(2);
    }

    ciphers == nullptr ? SSL_CTX_set_cipher_list(ctx,"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH") : SSL_CTX_set_cipher_list(ctx,ciphers);
    SSL_CTX_set_options(ctx,SSL_OP_NO_TICKET+SSL_OP_NO_SSLv3);    

    DEBS__("SSLCom::server_ctx_setup: loading default key/cert");
    priv == nullptr ? SSL_CTX_use_PrivateKey(ctx,certstore()->def_sr_key) : SSL_CTX_use_PrivateKey(ctx,priv);
    cert == nullptr ? SSL_CTX_use_certificate(ctx,certstore()->def_sr_cert) : SSL_CTX_use_certificate(ctx,cert);

        
    if (!SSL_CTX_check_private_key(ctx)) {
        ERRS__("SSLCom::server_ctx_setup: private key does not match the certificate public key\n");
        exit(5);
    }
 
    return ctx;
}

void SSLCom::certstore_setup(void ) {
    
    DIAS__("SSLCom: loading central certification store: start");
    
    SSLCom::sslcom_certstore_ = new SSLCertStore();
    bool ret = SSLCom::certstore()->load();
    
    if(! ret) {
        FATS__("Failure loading certificates, bailing out.");
        exit(2);
    }
    
    certstore()->def_cl_ctx = client_ctx_setup();
    DIAS__("SSLCom: default ssl client context: ok");
    
    if(certstore()->def_cl_capath.size() > 0) {
      int r = SSL_CTX_load_verify_locations(certstore()->def_cl_ctx,nullptr,certstore()->def_cl_capath.c_str());
      DIA__("SSLCom: loading default certification store: %s", r > 0 ? "ok" : "failed");
      if(r <= 0) {
	log_if_error2(WAR,"SSLCom::certstore_setup");
      }
    } else {
      WARS__("SSLCom: loading default certification store: path not set!");      
    }
    

    certstore()->def_sr_ctx = server_ctx_setup();
    DIAS__("SSLCom: default ssl server context: ok");
    
}

bool SSLCom::com_status() {
    if(TCPCom::com_status()) {
        if(opt_bypass) {
	    DIAS___("SSLCom::com_status: L4 OK, bypassed")
	    return true;
	}
      
        bool r = sslcom_status();
        // T_DIA___("sslcom_status_ok",1,"SSLCom::com_status: returning %d",r);
        
        if(r) {
            DIAS___("SSLCom::com_status: L4 and SSL layers OK")
        } else {
            DEBS___("SSLCom::com_status: L4 OK, but SSL layer not ready.")
        }
        
        DEB___("SSLCom::com_status: returning %d",r);
        return r;
    }
    
    // T_DIAS___("sslcom_status_nok",1,"SSLCom::com_status: returning 0");
    DEBS___("SSLCom::com_status: L4 layer not ready, returning 0");
    return false;
}
