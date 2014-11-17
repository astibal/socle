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

#include <sslcom.hpp>
#include <logger.hpp>


#include <cstdio>

#include <crc32.hpp>
#include <display.hpp>
#include <buffer.hpp>

std::once_flag SSLCom::openssl_thread_setup_done;
std::once_flag SSLCom::certstore_setup_done;
SSLCertStore*  SSLCom::sslcom_certstore_;


int SSLCom::counter_ssl_connect = 0;
int SSLCom::counter_ssl_accept = 0;

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
    for ( i = 0; i < CRYPTO_num_locks( ); i++ ) {
        MUTEX_CLEANUP ( mutex_buf[i] );
    }
    free ( mutex_buf );
    mutex_buf = NULL;
    return 1;
}



void SSLCom::static_init() {

    baseCom::static_init();

    DEBS_("SSL: Static INIT");

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


void SSLCom::init()  {
	
	TCPCom::init();
}

void SSLCom::init_client() {
	
	const SSL_METHOD *method;
	
	method = TLSv1_client_method();

	sslcom_ctx = SSL_CTX_new (method);	
    SSL_CTX_set_cipher_list(sslcom_ctx,"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
	
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

    sslcom_ssl = SSL_new(sslcom_ctx);
    SSL_set_mode(sslcom_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
}


void SSLCom::init_server() {
	
	const SSL_METHOD *method;
	
	DEBS_("SSLCom::init_server");
	
    if(sslcom_ctx) {
        SSL_CTX_free(sslcom_ctx);
    }
    if(sslcom_ssl) {
        SSL_free(sslcom_ssl);
    }
    
	method = TLSv1_server_method();
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
        DEB_("SSLCom::init_server[%x]: loading preferred key/cert",this);
        SSL_CTX_use_PrivateKey(sslcom_ctx,sslcom_pref_key);
        SSL_CTX_use_certificate(sslcom_ctx,sslcom_pref_cert);
        
    } else {
        DEB_("SSLCom::init_server[%x]: loading default key/cert",this);
        SSL_CTX_use_PrivateKey(sslcom_ctx,certstore()->def_sr_key);
        SSL_CTX_use_certificate(sslcom_ctx,certstore()->def_sr_cert);
    }
        
	if (!SSL_CTX_check_private_key(sslcom_ctx)) {
		ERRS_("Server: Private key does not match the certificate public key\n");
		exit(5);
	}	

	sslcom_ssl = SSL_new(sslcom_ctx);
    SSL_set_mode(sslcom_ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
	
	SSL_set_fd (sslcom_ssl, sslcom_fd);
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
	
    X509_NAME* x509_name = X509_get_subject_name(peer);
    X509_NAME_get_text_by_NID(x509_name,NID_commonName, peer_CN, 256);
// 	X509_NAME_oneline(X509_get_subject_name(peer),peer_CERT,1024);
//	DIA_("Peer certificate:\n%s",peer_CERT);
	
	DIA_("peer CN: %s",peer_CN);
	if(host != NULL) {
		DIA_("peer host: %s",host);
		
		if ( strcasecmp ( peer_CN,host ) ) {
		DIAS_( "Common name doesn't match host name" );
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

    DUM_("SSLCom::readable[%d]: sslcom_read_blocked_on_write: %d",s,sslcom_read_blocked_on_write);
    DUM_("SSLCom::readable[%d]: sslcom_write_blocked_on_read: %d",s,sslcom_write_blocked_on_read);  
    
	if (r) {
		DUM_("SSLCom::readable[%d]: %d",s,r);
	} else {
		DEB_("SSLCom::readable[%d]: %d",s,r);
	}
	
	return r;
};
bool SSLCom::writable(int s) { 
    // 	bool r  = ( sslcom_read_blocked_on_write ||  !sslcom_write_blocked_on_read ||  sslcom_waiting ); 	
	
    bool r = !sslcom_write_blocked_on_read;
    sslcom_write_blocked_on_read = false;
    
	DUM_("SSLCom::writable[%d]: sslcom_read_blocked_on_write: %d",s,sslcom_read_blocked_on_write);
    DUM_("SSLCom::writable[%d]: sslcom_write_blocked_on_read: %d",s,sslcom_write_blocked_on_read);  
	
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
	
    upgrade_server_socket(sockfd);
    
    if (SSL_accept (sslcom_ssl) > 0) {
        DUM_("SSLCom::accept_socket[%d]: success at 1st attempt.",sockfd);
    } else {
        DUM_("SSLCom::accept_socket[%d]: need to call later.",sockfd);
    }
}

void SSLCom::delay_socket(int sockfd) {
    // we need to know even delayed socket
    sslcom_fd = sockfd;
}


int SSLCom::upgrade_server_socket(int sockfd) {

    sslcom_fd = sockfd;
    sslcom_waiting = true;
    unblock(sslcom_fd);
    
    init_server();
    
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
	
	if (sslcom_ssl == NULL) {
		WARS_("SSLCom::ssl_waiting: sslcom_ssl = NULL");
		exit(1);
		return 0;
	}
	
	int r = 0;
	
	if (!sslcom_server) {

        if(! waiting_peer_hello()) {
             return 0;
        }
        
		r = SSL_connect(sslcom_ssl);
        
        //debug counter
        SSLCom::counter_ssl_connect++;
        
		op = op_connect;
	} 
	else if(sslcom_server) {
		r = SSL_accept(sslcom_ssl);
        
        SSLCom::counter_ssl_accept++;
        
		op = op_accept;
	}
		

	if (r == -1) {
		int err = SSL_get_error(sslcom_ssl,r);
		if (err == SSL_ERROR_WANT_READ) {
			DUM_("SSL_%s: want read",op);
			
 			sslcom_waiting = true;
//             forced_read(true);
// 			sslcom_waiting_read = true;
 			return 1;
		}
		else if (err == SSL_ERROR_WANT_WRITE) {
			DUM_("SSL_%s: want write",op);
			
 			sslcom_waiting = true;
//             forced_write(true);
// 			    sslcom_waiting_write = true;
 			return 1;
		}
		else {
            DIA_("SSL_%s: error: %d",op,err);
 			sslcom_waiting = true;
 			return 0;
		}
 
		
	} else if (r < -1) {
		DIA_("SSL failed: %s",op);
		
		//unclean shutdown
		sslcom_waiting = false;
		SSL_shutdown(sslcom_ssl);
		return -1;
		
	} else if (r == 0) {
		DIA_("SSL failed: %s",op);
		// shutdown OK, but connection failed
		sslcom_waiting = false;		
		return -1;
	}
	
	DEB_("SSLCom::ssl_waiting: operation succeeded: %s", op);
	sslcom_waiting = false;	

	if(!sslcom_server) {
		check_cert(ssl_waiting_host);
	}
	
	
	return r;
	
}

bool SSLCom::waiting_peer_hello()
{
    if(sslcom_peer_hello_received) {
        DUMS_("SSLCom::waiting_peer_hello: already called, returning true");
        return true;
    }
    
    DIAS_("SSLCom::waiting_peer_hello: called");
    if(peer()) {
        SSLCom *p = static_cast<SSLCom*>(peer());
        if(p != nullptr) {
            if(p->sslcom_fd > 0) {
                DIA_("SSLCom::waiting_peer_hello: reading max %d bytes from peer socket %d",2048,p->sslcom_fd);
                int red = ::recv(p->sslcom_fd,sslcom_peer_hello_buffer,1500,MSG_PEEK);
                if (red > 0) {
                    DIA_("SSLCom::waiting_peer_hello: %d bytes in buffer for hello analysis",red);
                    sslcom_peer_hello_received = true;
                    DEB_("SSLCom::waiting_peer_hello: ClientHello data:\n%s",hex_dump(sslcom_peer_hello_buffer,red).c_str());
                    
                    parse_peer_hello(sslcom_peer_hello_buffer,red);
                    
                } else {
                    DIA_("SSLCom::waiting_peer_hello: %d bytes",red);
                }
                
            } else {
                DIAS_("SSLCom::waiting_peer_hello: SSLCom peer doesn't have sslcom_fd set");
            }
        } else {
            DIAS_("SSLCom::waiting_peer_hello: peer not SSLCom type");
        }
    } else {
        DIAS_("SSLCom::waiting_peer_hello: no peers");
    }
    
    return sslcom_peer_hello_received;
}

bool SSLCom::parse_peer_hello(unsigned char* ptr, unsigned int len) {

    bool ret = false;
    
    uint8_t content_type = 0;
    
    if(len >= 34) {
        buffer b = buffer(ptr,len);
        buffer session_id = buffer();
        unsigned int curpos = 0;
        
        unsigned char message_type = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char);
        unsigned char version_maj = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char);
        unsigned char version_min = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char);
        
        unsigned short message_length = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
        
        
        DIA_("SSLCom::parse_peer_hello: received message type %d, version %d.%d, length %d",message_type,version_maj, version_min, message_length);
        
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
                DIA_("SSLCom::parse_peer_hello: handshake (type %u), version %u.%u, length %u",handshake_type,handshake_version_maj,handshake_version_min,handshake_length);
                ret = true;
            }
            
            if(session_id_length > 0) {
                session_id = b.view(curpos,session_id_length); curpos+=session_id_length;
                DEB_("SSLCom::parse_peer_hello: session_id (length %d):\n%s",session_id_length, hex_dump(session_id.data(),session_id.size()).c_str());
            } else {
                DEBS_("SSLCom::parse_peer_hello: no session_id found.");
            }
            
            unsigned short ciphers_length = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
            curpos += ciphers_length; //skip ciphers
            unsigned char compression_length = b.get_at<unsigned char>(curpos); curpos+=sizeof(unsigned char);
            curpos += compression_length; // skip compression methods

            DEB_("SSLCom::parse_peer_hello: ciphers length %d, compression length %d",ciphers_length,compression_length);
            
            /* extension section */
            unsigned short extensions_length = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
            DEB_("SSLCom::parse_peer_hello: extensions payload length %d",extensions_length);
            
            if(extensions_length > 0) {

                // minimal extension size is 5 (2 for ID, 2 for len)
                while(curpos + 4 < b.size()) {
                    curpos += parse_peer_hello_extensions(b,curpos);
                }
            }
        }
    }
    
    return ret;
}

unsigned short SSLCom::parse_peer_hello_extensions(buffer& b, unsigned int curpos) {

    unsigned short ext_id = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
    unsigned short ext_length = ntohs(b.get_at<unsigned short>(curpos)); curpos+=sizeof(unsigned short);
    
    DEB_("SSLCom::parse_peer_hello_extensions: extension id 0x%x, length %d", ext_id, ext_length);

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
                
                DIA_("SSLCom::parse_peer_hello_extensions:    SNI hostname: %s",s.c_str());
                SSL_set_tlsext_host_name(sslcom_ssl,s.c_str());
            }
            
            break;
    }
    
    return ext_length + 4;  // +4 for ext_id and ext_length
}



#pragma GCC diagnostic ignored "-Wpointer-arith"
#pragma GCC diagnostic push

int SSLCom::read ( int __fd, void* __buf, size_t __n, int __flags )  {
	
	//this one will be much trickier than just single call of SSL_read
	//return SSL_read (sslcom_ssl,__buf,__n);
	
	int total_r = 0;
    int rounds = 0;
	
	DUM_("SSLCom::read[%d]: about to read  max %4d bytes",__fd,__n);
	
	// non-blocking socket can be still opening 
	if( sslcom_waiting ) {
		int c = waiting();
        if (c == 0) {
            DEB_("SSLCom:: read[%d]: ssl_waiting() returned %d: still waiting",__fd,c);
            return -1;
        } else 
        if (c < 0) {
            DIA_("SSLCom:: read[%d]: ssl_waiting() returned %d: unrecoverable!",__fd,c);
            return 0;
        }
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
			DEB_("SSLCom::read[%d]: reached buffer capacity of %4d bytes",__fd,__n);
            
            // this is tricky one :) 
            // I have spent quite couple of hours of troubleshooting this:
            // ... 
            // We have to break here, since write buffer is full
            // BUT 
            // openssl already has it internally 
            // => select won't return this socket as in read_set == no reads anymore !!!
            // => we have to have mechanism which will enforce read in the next round 
			forced_read(true);
		}
		
//         sslcom_read_blocked_on_write=0;
//         sslcom_read_blocked=0;

        //again:
        int r = SSL_read (sslcom_ssl,__buf+total_r,__n-total_r);
// 		if (r > 0) return r;

		if(r == 0) {
			DEBS_("SSLCom::read: SSL_read returned 0");
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
				
				DIA_("SSLCom::read [%d]: %4d bytes read:%d from ssl socket %s, %X",__fd,r,rounds,(r == (signed int)__n) ? "(max)" : "",
                                debug_log_data_crc ? socle_crc32(0,__buf,r) : 0
                );
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
					DEB_("SSLCom::read[%d]: want read: err=%d,read_now=%4d,total=%4d",__fd,err,r,total_r);
				}
				else {
					DEB_("SSLCom::read[%d]: want read: err=%d,read_now=%4d,total=%4d",__fd,err,r,total_r);
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
				INF_("SSLCom::read[%d]: want connect",__fd);
                
                if(total_r > 0) return total_r;
				return r;

			case SSL_ERROR_WANT_ACCEPT:
				INF_("SSLCom::read[%d]: want accept",__fd);

                if(total_r > 0) return total_r;              
				return r;
				
				
			case SSL_ERROR_WANT_WRITE:
				DEB_("SSLCom::read[%d]: want write, last read retured %d, total read %4d",__fd,r,total_r);
				sslcom_read_blocked_on_write=1;
                forced_write(true);  // we can opportinistically enforce write operation regardless of select result
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
					DEB_("SSLCom::read[%d] problem: %d, read returned %4d",__fd,err,r);
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

	DEB_("SSLCom::read: total %4d bytes read",total_r);

	if(total_r == 0) {
		DIAS_("SSLCom::read: logic error, total_r == 0");
	}
	
	return total_r;
}

int SSLCom::write ( int __fd, const void* __buf, size_t __n, int __flags )  {

    if(__n == 0) {
        EXT_("SSLCom::write[%d]: called: about to write %d bytes",__fd,__n);    
    } else {
        DEB_("SSLCom::write[%d]: called: about to write %d bytes",__fd,__n);	
    }
	
	//this one will be much trickier than just single call of SSL_read
	// return SSL_write(sslcom_ssl, __buf, __n);

// 	// non-blocking socket can be still opening 
	if( sslcom_waiting ) {
		int c = waiting();
		if (c == 0) {
			DEB_("SSLCom::write[%d]: ssl_waiting() returned %d: still waiting",__fd,c);
			return 0;
		} else 
        if (c < 0) {
            DIA_("SSLCom::write[%d]: ssl_waiting() returned %d: unrecoverable!",__fd,c);
            return -1;
        }
	}	
	
    sslcom_write_blocked_on_read=0;
    int normalized__n = 20480;
    void *ptr = (void*)__buf;

    if(__n == 0) {
        EXT_("SSLCom::write[%d]: attempt to send %d bytes",__fd,__n);
    } else {
        DEB_("SSLCom::write[%d]: attempt to send %d bytes",__fd,__n);
    }
    if ( __n < 20480) {
        normalized__n = __n;
    }

    if (__n <= 0 ) {
         return 0;
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
			DIA_("SSLCom::write[%d]: %4d bytes written to the ssl socket %s, %X",__fd,r, r != (signed int)__n ? "(incomplete)" : "",
                            debug_log_data_crc ? socle_crc32(0,__buf,r) : 0
            );
			is_problem = false;
            
            sslcom_write_blocked_on_read = 0;
            
			break;
			
		/* We would have blocked */
		case SSL_ERROR_WANT_WRITE:
			DIA_("SSLCom::write[%d] want write: %d (written %4d)",__fd,err,r);	

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
			DIA_("SSLCom::write[%d] want read: %d (written %4d)",__fd,err,r);	
			sslcom_write_blocked_on_read=1;
            forced_read(true);
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
    
	if (sslcom_ctx) {
        SSL_CTX_free(sslcom_ctx);
        sslcom_ctx = nullptr;
    }
} 


int SSLCom::upgrade_client_socket(int sock) {

    init_client();
    
    if(sslcom_ssl == NULL) {
        ERRS_("Failed to create SSL structure!");
    }
//  SSL_set_fd (sslcom_ssl, sock);
    
    sslcom_sbio = BIO_new_socket(sock,BIO_NOCLOSE);
    if (sslcom_sbio == NULL) {
        ERR_("BIO allocation failed for socket %d",sock)
    }
    
    SSL_set_bio(sslcom_ssl,sslcom_sbio,sslcom_sbio);    

    bool ch = waiting_peer_hello();
    
    if(ch) {
        int r = SSL_connect(sslcom_ssl);        
        if(r <= 0 && is_blocking(sock)) {
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
            return sock;    
        }
        
        DEBS_("connection succeeded");  
        sslcom_waiting = false;
        sslcom_fd = sock;
        
        //ssl_waiting_host = (char*)host;    
        check_cert(nullptr);
        
    }
    
   
    return sock;
    

}


int SSLCom::connect ( const char* host, const char* port, bool blocking )  {
	int sock = TCPCom::connect( host, port, blocking );
	
// 	if (SSL_CTX_set_session_id_context(sslcom_ctx,
// 								   (const unsigned char*)sslcom_server_session_id_context,
// 									strlen(sslcom_server_session_id_context)) == 0) {
// 
// 		ERRS_("Setting session ID context failed!");
// 	}
	return upgrade_client_socket(sock);
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

bool SSLCom::com_status() {
    if(TCPCom::com_status()) {
        bool r = sslcom_status();
        // T_DIA_("sslcom_status_ok",1,"SSLCom::com_status: returning %d",r);
        
        if(r) {
            DIAS_("SSLCom::com_status: transport layer OK")
        } else {
            DEBS_("SSLCom::com_status: SSL layer not ready.")
        }
        
        DEB_("SSLCom::com_status: returning %d",r);
        return r;
    }
    
    // T_DIAS_("sslcom_status_nok",1,"SSLCom::com_status: returning 0");
    DEBS_("SSLCom::com_status: lower transport layer not ready, returning 0");
    return false;
}
