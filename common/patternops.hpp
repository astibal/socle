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

#include <string>
#include <vector>
#include <tuple>
#include <buffer.hpp>
#include <display.hpp>

typedef std::pair<unsigned char,buffer*> side_buffer_ptr;


template <class SourceType>
class Flow {
    std::vector<std::pair<SourceType,buffer*>> flow_; // store flow data ... ala follow tcp stream :) 
                                     // Flowdata::side_ doesn't have to be necesarilly L or R
                                     
public:
    std::vector<std::pair<SourceType,buffer*>>& flow() { return flow_; }
    std::vector<std::pair<SourceType,buffer*>>& operator() () { return flow(); }

    unsigned int append(SourceType src,buffer& b) { return append(src,b.data(),b.size());};
    unsigned int append(SourceType src,const void* data, size_t len) {
        if(flow_.size() == 0) {
            auto b = new buffer(data,len);
            // src initialized by value, buffer is pointer
            std::pair<SourceType,buffer*> t(src,b);
            flow_.push_back(t);
        }
        else if (flow_.back().first == src) {
            flow_.back().second->append(data,len);
        }
        else if (flow_.back().first != src) {
            auto b = new buffer(data,len);
            // src initialized by value, buffer is pointer
            std::pair<SourceType,buffer*> t(src,b);
            flow_.push_back(t);
        }
    };
    
    virtual ~Flow() {
        for( auto i = 0; i < flow_.size(); i++) {
            buffer* b = flow_.at(i).second;
            delete b;
        }
    }
};


typedef typename std::pair<int,int> range;
typedef typename std::vector<range> vector_range;

const range NULLRANGE(0,-1);

std::string rangetos(range r) { return string_format("<%d,%d>",r.first,r.second); }

// ----


class baseMatch {
public:
    virtual range match(unsigned char* str, unsigned int max_len = 0) { return NULLRANGE; };
    virtual range match(buffer& b) {
        return match(b.data(),b.size());
    }
};

class simpleMatch : public baseMatch {
    std::string expr_;
    
    range last_result_;
    std::string last_query_;
public:    
    simpleMatch(const char* e) : expr_(e), last_result_(NULLRANGE) {}
    simpleMatch(std::string& e) : expr_(e), last_result_(NULLRANGE) {}
    
    virtual range match(const char* str, unsigned int max_len = 0);
    virtual range operator() () { return last_result_; }
    virtual range operator() (const char* str, unsigned int max_len = 0) { return match(str,max_len); };
    
    virtual range next(int max_len = 0) {
        
        if (last_result_ == NULLRANGE) {
            return NULLRANGE;
        }
        
        int scope = last_query_.size() - last_result_.second;
        if(max_len != 0) {
            scope = max_len;
        }
        int from = last_result_.second+1;
        
        //std::cout << "Looking in '"<< last_query_ << "' for '" << expr_ << "' from " << from << " size " <<  scope << "\n";
        
        std::string tmp = last_query_.substr(from,scope);
        int pos = tmp.find(expr_.c_str());
        
        //std::cout << "Found at " << pos << "\n";
        
        if(pos != std::string::npos) {
            last_result_ = range(from+pos,from+pos+expr_.size()-1);
        } else {
            last_result_ = NULLRANGE;
        }
        
        return last_result_;
    };
};

range simpleMatch::match(const char* str, unsigned int max_len) { 
    
    last_query_ = "";
    last_result_ = NULLRANGE;
    
    if(max_len == 0) {
        last_query_.append(str);
    } else {
        last_query_.append(str,max_len); 
    }
    
    unsigned int where = last_query_.find(expr_);
    if(where == std::string::npos) {
        last_result_ = NULLRANGE;
    }
    
    last_result_ = range(where,where+expr_.size()-1);
    
    return last_result_;
};

template <class SourceType,class MatchType>
class flowMatch {
    unsigned int level;                                                        // add layer of dependency
    std::vector<std::pair<SourceType,MatchType*>>  signature_;                // series of L/R/X matches to be satisfied

public:    
    void add(SourceType s, MatchType* m) { signature_.push_back(std::pair<SourceType,MatchType*>(s,m)); };
    
    std::vector<range> match(Flow<SourceType>* f) {
        
        std::vector<range> ret;
        ret.push_back(NULLRANGE);   // prepare for only partial match
        
        int flow_match_start = -1;
        int flow_match_end = -1;
        int flow_match_skipped = 0;
        
        int signature_last_match = -1;
        int cur_flow = 0;
        
        for( ; cur_flow < f->flow().size(); cur_flow++) {
            auto ff = f->flow().at(cur_flow);
            
            SourceType ff_src = ff.first;
            buffer*    ff_buf = ff.second; 
            
            int sig_test = signature_last_match + 1;
            
            if(sig_test >= signature_.size()) {
                // we hit the end of  the signature!
                break;
            }
            
            // FIXME: check size and boundaries
            SourceType   sig_src = signature_.at(sig_test).first;
            MatchType* sig_match = signature_.at(sig_test).second;

            if ( ff_src == sig_src ) {
                range r = sig_match->match((const char*)ff_buf->data(),ff_buf->size());
                
                if( r != NULLRANGE) {
                    // yes! we have a (at least partial) hit
                    signature_last_match++;
                    ret.push_back(r);
                }
                else {
                    // no this is not a hit
                    if(signature_last_match >= 0) {
                        // if we already matched, increase skipped counter
                        flow_match_skipped++;
                    }
                }
            }
            else {
                // this flow entry is not for us
                continue;
            }
        }
        
        if(signature_last_match == signature_.size() - 1) {
            ret.erase(ret.begin());
            return ret;
        }
        
        return ret;
    }
};

