#ifndef LRPROXY_HPP
#define LRPROXY_HPP

#include <baseproxy.hpp>
#include <buffer.hpp>

class LRProxy: public TCPProxy {
	protected:
		void write_left_right();
		void write_right_left();
		
	public: 
		LRProxy();
		
		virtual void on_left_bytes(tcpHostCX*);
		virtual void on_right_bytes(tcpHostCX*);
};

#endif