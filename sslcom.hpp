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

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <basecom.hpp>
#include <sslcertstore.hpp>


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
    #define MUTEX_TYPE pthread_mutex_t
    #define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
    #define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
    #define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
    #define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
    #define THREAD_ID pthread_self( )
#else
    #error You must define mutex operations appropriate for your platform!
#endif

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic push

#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic push

/* This array will store all of the mutexes available to OpenSSL. */
static MUTEX_TYPE *mutex_buf = NULL ;
void locking_function ( int mode, int n, const char * file, int line );
unsigned long id_function ( void );


#pragma GCC diagnostic pop 
#pragma GCC diagnostic pop 

int THREAD_setup ( void );
int THREAD_cleanup ( void );

class SSLCom : public TCPCom {

protected:
	SSL_CTX* sslcom_ctx = NULL;
	SSL*     sslcom_ssl = NULL;
	BIO*	 sslcom_sbio = NULL;
    
    X509*     sslcom_pref_cert = NULL;
    EVP_PKEY* sslcom_pref_key  = NULL;
	
	// states of read/writes
	int sslcom_read_blocked_on_write=0;
	int sslcom_write_blocked_on_read=0;
	int sslcom_read_blocked=0;
	
	bool sslcom_waiting=true;
	bool sslcom_server=false;
	int sslcom_server_fd=0;
	int ssl_waiting();
	
	char* ssl_waiting_host = NULL;
	  
    // is the socket up or not
    bool sslcom_status_ = false;
    inline bool sslcom_status() { return sslcom_status_; }
    inline void sslcom_status(bool b) { sslcom_status_ = b; }
    
public:
    static std::once_flag openssl_thread_setup_done;
    
    // certificate store common across all SSCom instances
    static SSLCertStore* sslcom_certstore_;
    static void certstore_setup(void);
    static std::once_flag certstore_setup_done;    
    
    static SSLCertStore* certstore() { return sslcom_certstore_; };
    static void certstore(SSLCertStore* c) { if (sslcom_certstore_ != NULL) { delete sslcom_certstore_; }  sslcom_certstore_ = c; };
	
	virtual void static_init();
	virtual void init();
    virtual baseCom* replicate() { return new SSLCom(); } ;
    
	virtual void init_client();
	int upgrade_client_socket(int s);
    
    virtual void init_server();
    int upgrade_server_socket(int s);

	virtual bool check_cert(const char*);
	
	virtual bool readable (int s);
	virtual bool writable (int s);
	
	virtual void accept_socket ( int sockfd	);
    virtual int connect ( const char* host, const char* port, bool blocking = false );
	
	virtual int read ( int __fd, void* __buf, size_t __n, int __flags );
	virtual int write ( int __fd, const void* __buf, size_t __n, int __flags );
	
	virtual void cleanup();

    virtual bool com_status();
    
    virtual ~SSLCom() {};
};

#endif