# Socle README #

Socle stands for SOcket Library Ecosystem. Its is (so far) static library which could be used to simplify operation on sockets and (which is more important
from library philosophy) chaining them with other sockets.
In other words, Socle's main purpose is to make comfortable writing various proxy applications between 2 sockets.

# FEATURES #
* abstraction of socket operations with derivatives of baseCom class which is used solely as interface for socket operations (for example UDP/TCP/SSL)
* Connection and data abstraction with derivatives of baseHostCX which operates with data and application state and uses *Com objects as "communication controller"
* Chaining of baseHostCX into proxies (derivatives of baseProxy) which take care of data exchange between them (for example to copy from left socket to right and vice versa)

# DEVELOPMENT ROADMAP #

## 0.4.0 branch - stable
* stabilize/fix code, cleanups
* documentation and examples improvements
* no more changes, unless it's necessary

## 0.5.0 branch - testing
* more SSL debugs with 
  *SSL_set_msg_callback*  -- can be used to obtain state information for SSL objects created from ctx during connection setup and use
  *SSL_set_info_callback*  -- can be used to define a message callback function cb for observing all SSL/TLS protocol messages

* shapers
  implement *bucket system* to be used by proxy hierarchy

* DTLS support
  implement DTLSCom, DTLSMitmCom class to proxy also DTLS traffic

  
* Repository is owned by Ales Stibal <astib@mag0.net>