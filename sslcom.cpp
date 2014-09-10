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

#include <sslcom.hpp>
#include <logger.hpp>


#include <cstdio>

std::once_flag SSLCom::openssl_thread_setup_done;
std::once_flag SSLCom::certstore_setup_done;
SSLCertStore*  SSLCom::sslcom_certstore_;

void locking_function ( int mode, int n, const char * file, int line )  {
	
    if ( mode & CRYPTO_LOCK ) {
        MUTEX_LOCK ( mutex_buf[n] );
    } else {
        MUTEX_UNLOCK ( mutex_buf[n] );
    }
}

unsigned long id_function ( void ) {
	
    return ( ( unsigned long ) THREAD_ID );
}

int THREAD_setup ( void ) {
    int i;
    mutex_buf = ( MUTEX_TYPE * ) malloc ( CRYPTO_num_locks( ) * sizeof ( MUTEX_TYPE ) );
    if ( !mutex_buf ) {
		
		FATS_("OpenSSL threading support: cannot allocate mutex buffer");
        return 0;
    }
    for ( i = 0; i < CRYPTO_num_locks( ); i++ ) {
        MUTEX_SETUP ( mutex_buf[i] );
    }
    CRYPTO_set_id_callback ( id_function );
    CRYPTO_set_locking_callback ( locking_function );
	
	INFS_("OpenSSL threading support: enabled");
    return 1;
}

int THREAD_cleanup ( void ) {
    int i;
    if ( !mutex_buf ) {
        return 0;
    }
    CRYPTO_set_id_callback ( NULL );
    CRYPTO_set_locking_callback ( NULL );
    for ( i = 0; i < CRYPTO_num_locks( ); i++ ) {
        MUTEX_CLEANUP ( mutex_buf[i] );
    }
    free ( mutex_buf );
    mutex_buf = NULL;
    return 1;
}



void SSLCom::static_init() {

    baseCom::static_init();

    DIAS_("SSL: Static INIT");

	if(false) {	
		// make compiler happy
		mutex_buf = NULL;
		locking_function(0,0,NULL,0);
		id_function();
	}

	// call openssl threads support - only once from all threads!
	std::call_once (SSLCom::openssl_thread_setup_done ,THREAD_setup);
    std::call_once (SSLCom::certstore_setup_done ,SSLCom::certstore_setup);
	
	DIAS_("SSL: loading error strings");
	SSL_load_error_strings();
	
	DIAS_("SSL: loading algorithms");
	SSLeay_add_ssl_algorithms();
}


void SSLCom::init()  {
	
	TCPCom::init();
}

void SSLCom::init_client() {
	
	const SSL_METHOD *method;
	
	method = TLSv1_method();

	sslcom_ctx = SSL_CTX_new (method);	
	//SSL_CTX_set_cipher_list(sslcom_ctx,"EDH-RSA-DES-CBC3-SHA");
	
	if (!sslcom_ctx) {
		ERRS_("Client: Error creating SSL context!");
		exit(2);
	}
	
// 	if (SSL_CTX_use_certificate_file(sslcom_ctx, CL_CERTF, SSL_FILETYPE_PEM) <= 0) {
// 		ERRS_("Client: Error loading certificate!");
// 		exit(3);
// 	}
// 	if (SSL_CTX_use_PrivateKey_file(sslcom_ctx, CL_KEYF, SSL_FILETYPE_PEM) <= 0) {
// 		ERRS_("Client: Error loading private key!");
// 		exit(4);
// 	}

    DIA_("SSLCom::init_client[%x]: loading default key/cert",this);
    SSL_CTX_use_PrivateKey(sslcom_ctx,certstore()->def_cl_key);
    SSL_CTX_use_certificate(sslcom_ctx,certstore()->def_cl_cert);

	if (!SSL_CTX_check_private_key(sslcom_ctx)) {
		ERRS_("Client: Private key does not match the certificate public key\n");
		exit(5);
	}	

}


void SSLCom::init_server() {
	
	const SSL_METHOD *method;
	
	DEBS_("SSLCom::init_server");
	
	method = SSLv3_server_method();
	sslcom_ctx = SSL_CTX_new (method);	
	if (!sslcom_ctx) {
		ERRS_("Server: Error creating SSL context!");
		exit(2);
	}
	
// 	if (SSL_CTX_use_certificate_file(sslcom_ctx, SR_CERTF, SSL_FILETYPE_PEM) <= 0) {
// 		ERRS_("Server: Error loading certificate!");
// 		exit(3);
// 	}
// 	if (SSL_CTX_use_PrivateKey_file(sslcom_ctx, SR_KEYF, SSL_FILETYPE_PEM) <= 0) {
// 		ERRS_("Server: Error loading private key!");
// 		exit(4);
// 	}

    if (sslcom_pref_cert && sslcom_pref_key) {
        DIA_("SSLCom::init_server[%x]: loading preferred key/cert",this);
        SSL_CTX_use_PrivateKey(sslcom_ctx,sslcom_pref_key);
        SSL_CTX_use_certificate(sslcom_ctx,sslcom_pref_cert);
        
    } else {
        DIA_("SSLCom::init_server[%x]: loading default key/cert",this);
        SSL_CTX_use_PrivateKey(sslcom_ctx,certstore()->def_sr_key);
        SSL_CTX_use_certificate(sslcom_ctx,certstore()->def_sr_cert);
    }
        
	if (!SSL_CTX_check_private_key(sslcom_ctx)) {
		ERRS_("Server: Private key does not match the certificate public key\n");
		exit(5);
	}	

	sslcom_ssl = SSL_new(sslcom_ctx);
	
	SSL_set_fd (sslcom_ssl, sslcom_server_fd);
	SSL_accept (sslcom_ssl);	

	sslcom_server = true;
}

bool SSLCom::check_cert (const char* host) {
    X509 *peer;
    char peer_CN[256];

    if ( SSL_get_verify_result ( sslcom_ssl ) !=X509_V_OK ) {
        DIAS_( "check_cert: certificate doesn't verify" );
    }

    /*Check the cert chain. The chain length
      is automatically checked by OpenSSL when
      we set the verify depth in the ctx */

    /*Check the common name*/
    peer=SSL_get_peer_certificate ( sslcom_ssl );
	
	if(peer == NULL) {
		ERRS_("check_cert: unable to retrieve peer certificate");
		
		// cannot proceed, next checks require peer X509 data
		return false;
	};
	
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
// 	X509_NAME_oneline(X509_get_subject_name(peer),peer_CERT,1024);
//	DIA_("Peer certificate:\n%s",peer_CERT);
	
	DIA_("peer CN: %s",peer_CN);
	if(host != NULL) {
		DIA_("peer host: %s",host);
		
		if ( strcasecmp ( peer_CN,host ) ) {
		DIAS_( "Common name doesn't match host name" );
		}
	}
	
	// finally, SSL is up, set status flag
	sslcom_status(true);
	
	return true;
}


/* OK set  */
bool SSLCom::readable(int s) { 
	bool r = (
		( ( FD_ISSET(s,&read_socketSet)  &&  sslcom_write_blocked_on_read) ) ||
          ( FD_ISSET(s,&read_socketSet) && !sslcom_read_blocked_on_write ) ||
           sslcom_waiting
		); 
	
	if (r) {
		DUM_("SSLCom::readable[%d]: %d",s,r);
	} else {
		DEB_("SSLCom::readable[%d]: %d",s,r);
	}
	
	return r;
};
bool SSLCom::writable(int s) { 
	//return (FD_ISSET(s,&write_socketSet) || (sslcom_write_blocked_on_read && FD_ISSET(s,&read_socketSet))); 
	bool r (
		  ( ( FD_ISSET(s,&write_socketSet) && sslcom_read_blocked_on_write) ) ||
		    ( FD_ISSET(s,&write_socketSet) && !sslcom_write_blocked_on_read ) || 
		    sslcom_waiting
		  ); 	
	
	DUM_("SSLCom::writable[%d]: read_set ready: %d",s,FD_ISSET(s,&read_socketSet));
	DUM_("SSLCom::writable[%d]: write_set ready: %d",s,FD_ISSET(s,&write_socketSet));
	DUM_("SSLCom::writable[%d]: sslcom_read_blocked_on_write: %d",s,sslcom_read_blocked_on_write);	
	
	if (r) {
		DUM_("SSLCom::writable[%d]: %d",s,r);
	} else {
		DEB_("SSLCom::writable[%d]: %d",s,r);
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

	DIA_("SSLCom::accept_socket: %d",sockfd)
	
	TCPCom::accept_socket(sockfd);
	
	sslcom_server_fd = sockfd;
	sslcom_waiting = true;
	unblock(sslcom_server_fd);
	
	init_server();
}


int SSLCom::ssl_waiting() {

	const char* op_accept = "accept";
	const char* op_connect = "connect";
	const char* op_unknown = "?unknown?";
	
	const char* op = op_unknown;
	
	if (sslcom_ssl == NULL) {
		WARS_("SSLCom::ssl_waiting: sslcom_ssl = NULL");
		exit(1);
		return 0;
	}
	
	int r = 0;
	
	if (!sslcom_server) {
		r = SSL_connect(sslcom_ssl);
		op = op_connect;
	} 
	else if(sslcom_server) {
		r = SSL_accept(sslcom_ssl);
		op = op_accept;
	}
		

	if (r == -1) {
		int err = SSL_get_error(sslcom_ssl,r);
		if (err == SSL_ERROR_WANT_READ) {
			DUM_("SSL READ pending: %s",op);
			
 			sslcom_waiting = true;
// 			sslcom_waiting_read = true;
 			return 1;
		}
		else if (err == SSL_ERROR_WANT_WRITE) {
			DUM_("SSL WRITE pending: %s",op);
			
 			sslcom_waiting = true;
// 			sslcom_waiting_write = true;
 			return 1;
		}
		else {
 			sslcom_waiting = false;
 			return 1;
		}
 
		
	} else if (r < -1) {
		DIA_("SSL failed: %s",op);
		
		//unclean shutdown
		sslcom_waiting = false;
		SSL_shutdown(sslcom_ssl);
		return 0;
		
	} else if (r == 0) {
		DIA_("SSL failed: %s",op);
		// shutdown OK, but connection failed
		sslcom_waiting = false;		
		return 0;
	}
	
	DEB_("SSL operation succeeded: %s",op);
	sslcom_waiting = false;	

	if(!sslcom_server) {
		check_cert(ssl_waiting_host);
	}
	
	
	return r;
	
}


#pragma GCC diagnostic ignored "-Wpointer-arith"
#pragma GCC diagnostic push

int SSLCom::read ( int __fd, void* __buf, size_t __n, int __flags )  {
	
	//this one will be much trickier than just single call of SSL_read
	//return SSL_read (sslcom_ssl,__buf,__n);
	
	int total_r = 0;
	
	DUM_("SSLCom::read[%d]: about to read  max %d bytes",__fd,__n);
	
	// non-blocking socket can be still opening 
	if( sslcom_waiting ) {
		int c = ssl_waiting();
		if (c <= 0) return c;
	}
	
	// if we are peeking, just do it and return, no magic done is here
	if ((__flags & MSG_PEEK) != 0) {
        int peek_r = SSL_peek(sslcom_ssl,__buf,__n);
        if(peek_r > 0) {
            DEB_("SSLCom::read[%d]: peek returned %d",__fd, peek_r);
        } else {
            EXT_("SSLCom::read[%d]: peek returned  %d",__fd, peek_r);
        } 
        
        return peek_r;
    }
	
    do {
		
		if(total_r >= (int)__n) {
			DEB_("SSLCom::read[%d]: reached buffer capacity of %d bytes",__fd,__n);
			break;
		}
		
//         sslcom_read_blocked_on_write=0;
//         sslcom_read_blocked=0;

        int r = SSL_read (sslcom_ssl,__buf+total_r,__n-total_r);
// 		if (r > 0) return r;

		if(r == 0) {
			DIAS_("SSLCom::read: SSL_read returned 0");
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
				
				DEB_("SSLCom::read[%d]: %d bytes read from ssl socket",__fd,r);
				total_r += r;
				
				sslcom_read_blocked_on_write=0;
				sslcom_read_blocked=0;				
				break;
				
			case SSL_ERROR_ZERO_RETURN:
				DEB_("SSLCom::read[%d]: zero returned",__fd);
				SSL_shutdown (sslcom_ssl);
				return r;
				
			case SSL_ERROR_WANT_READ:
				if(r == -1){
					DUM_("SSLCom::read[%d]: want read: err=%d,read_now=%d,total=%d",__fd,err,r,total_r);
				}
				else {
					DEB_("SSLCom::read[%d]: want read: err=%d,read_now=%d,total=%d",__fd,err,r,total_r);
				}
				sslcom_read_blocked=1;
				
				if(total_r > 0) return total_r;
				return r;

				/* We get a WANT_WRITE if we're
				trying to rehandshake and we block on
				a write during that rehandshake.

				We need to wait on the socket to be
				writeable but reinitiate the read
				when it is */
				
			case SSL_ERROR_WANT_CONNECT:
				DEB_("SSLCom::read[%d]: want connect",__fd);
				if(total_r > 0) return total_r;
				return r;

			case SSL_ERROR_WANT_ACCEPT:
				DEB_("SSLCom::read[%d]: want accept",__fd);
				if(total_r > 0) return total_r;
				return r;
				
				
			case SSL_ERROR_WANT_WRITE:
				DEB_("SSLCom::read[%d]: want write, last read retured %d, total read %d",__fd,r,total_r);
				sslcom_read_blocked_on_write=1;
				if(total_r > 0) return total_r;
				return r;
			
			case SSL_ERROR_WANT_X509_LOOKUP:
				DEB_("SSLCom::read[%d]: want x509 lookup",__fd);
				if(total_r > 0) return total_r;
				return r;
				
			case SSL_ERROR_SYSCALL:
				DEB_("SSLCom::read[%d]: syscall errorq",__fd);
				if(total_r > 0) return total_r;
				return r;
				
			default:
				if (r != -1 && err != 1) {
					DEB_("SSLCom::read[%d] problem: %d, read returned %d",__fd,err,r);
				}
	// 			SSL_shutdown (sslcom_ssl);
				if(total_r > 0) return total_r;
				return r;
        }

        /* We need a check for read_blocked here because
           SSL_pending() doesn't work properly during the
           handshake. This check prevents a busy-wait
           loop around SSL_read() */
		
		
    //} while ( SSL_pending ( sslcom_ssl ) && !sslcom_read_blocked );
    } while ( SSL_pending ( sslcom_ssl ) && !sslcom_read_blocked );

	DEB_("SSLCom::read: total %d bytes read",total_r);

	if(total_r == 0) {
		DIAS_("SSLCom::read: logic error, total_r == 0");
	}
	
	return total_r;
}

int SSLCom::write ( int __fd, const void* __buf, size_t __n, int __flags )  {
	
	DEB_("SSLCom::write[%d]: called: about to write %d bytes",__fd,__n);	
	
	//this one will be much trickier than just single call of SSL_read
	// return SSL_write(sslcom_ssl, __buf, __n);

// 	// non-blocking socket can be still opening 
	if( sslcom_waiting ) {
		int c = ssl_waiting();
		if (c <= 0) {
			DEB_("SSLCom::write[%d]: ssl_waiting() <= 1, returning",__fd);
			return 0;
		}
	}	
	
    sslcom_write_blocked_on_read=0;
    int normalized__n = 2048;
    void *ptr = (void*)__buf;

    DEB_("SSLCom::write[%d]: attempt to send %d bytes",__fd,__n);
    if ( __n < 2048) {
        normalized__n = __n;
    }

    again:

    /* Try to write */
    int r = SSL_write (sslcom_ssl,ptr,normalized__n);

// 	if (r > 0) return r;
	
	int err = SSL_get_error ( sslcom_ssl,r );
	bool is_problem = true;
	
    switch ( err ) {

		/* We wrote something*/
		case SSL_ERROR_NONE:
			DEB_("SSLCom::write[%d]: %d bytes written to the ssl socket",__fd,r);
			is_problem = false;
			break;
			
		/* We would have blocked */
		case SSL_ERROR_WANT_WRITE:
			DEB_("SSLCom::write[%d] want write: %d (written %d)",__fd,err,r);	

			if (r > 0) {
				normalized__n = normalized__n - r;
				ptr += r;
			} else {
				DUM_("SSLCom::write[%d] want write: repeating last operation",__fd);	
			}

			goto again;
			break;

		/* We get a WANT_READ if we're
			trying to rehandshake and we block on
			write during the current connection.

			We need to wait on the socket to be readable
			but reinitiate our write when it is */
		case SSL_ERROR_WANT_READ:
			DEB_("SSLCom::write[%d] want read: %d (written %d)",__fd,err,r);	
			sslcom_write_blocked_on_read=1;
			break;

			/* Some other error */
		default:
			DEB_("SSLCom::write[%d] problem: %d",__fd,err);


	}
	
	if (is_problem) {
		return 0;
	}
	
	return r;
};

#pragma GCC diagnostic pop

void SSLCom::cleanup()  {

	TCPCom::cleanup();
	
	if(sslcom_ssl) 	SSL_free (sslcom_ssl);
	if (sslcom_ctx) SSL_CTX_free(sslcom_ctx);
}

int SSLCom::connect ( const char* host, const char* port, bool blocking )  {
	int sock = TCPCom::connect( host, port, blocking );
	
// 	if (SSL_CTX_set_session_id_context(sslcom_ctx,
// 								   (const unsigned char*)sslcom_server_session_id_context,
// 									strlen(sslcom_server_session_id_context)) == 0) {
// 
// 		ERRS_("Setting session ID context failed!");
// 	}
	
	init_client();
	
	sslcom_ssl = SSL_new(sslcom_ctx);
	if(sslcom_ssl == NULL) {
		ERRS_("Failed to create SSL structure!");
	}
// 	SSL_set_fd (sslcom_ssl, sock);
	
    sslcom_sbio = BIO_new_socket(sock,BIO_NOCLOSE);
	if (sslcom_sbio == NULL) {
		ERR_("BIO allocation failed for socket %d",sock)
	}
	
    SSL_set_bio(sslcom_ssl,sslcom_sbio,sslcom_sbio);	

	int r = SSL_connect(sslcom_ssl);
	if(r <= 0 && blocking) {
		ERR_("SSL connect error on socket %d",sock);
		close(sock);
		return -1;
	}
	else if (r <= 0) {
		/* non-blocking may return -1 */
		
		if (r == -1) {
			int err = SSL_get_error(sslcom_ssl,r);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_READ) {
				DUMS_("SSL connect pending");
				
				sslcom_waiting = true;
				return sock;
			}
		}
		
		
		ssl_waiting_host = (char*)host;
		return sock;
		
	}
	
	DEBS_("connection succeeded");	
	sslcom_waiting = false;
	
    check_cert(host);
	
	return sock;
}



void SSLCom::certstore_setup(void ) {
    
    DIAS_("SSLCom: loading central certification store: start");
    
    SSLCom::sslcom_certstore_ = new SSLCertStore();
    bool ret = SSLCom::certstore()->load();
    
    if(! ret) {
        FATS_("Failure loading certificates, bailing out.");
        exit(2);
    }
    
    DIAS_("SSLCom: loading central certification store: ok");
}


