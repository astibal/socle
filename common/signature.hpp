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
#include <regex>
#include <vector>
#include <tuple>
#include <buffer.hpp>
#include <display.hpp>
#include <logger.hpp>

typedef std::pair<unsigned char,buffer*> side_buffer_ptr;


template <class SourceType>
class Flow {
    std::vector<std::pair<SourceType,buffer*>> flow_; // store flow data ... ala follow tcp stream :) 
                                     // Flowdata::side_ doesn't have to be necesarilly L or R
                                     
public:
    std::vector<std::pair<SourceType,buffer*>>& flow() { return flow_; }
    std::vector<std::pair<SourceType,buffer*>>& operator() () { return flow(); }

    unsigned int append(SourceType src,buffer& b) { return append(src,b.data(),b.size());};
    unsigned int append(SourceType src,buffer* pb) { return append(src,pb->data(),pb->size());};
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
        
        return len;
    };
    
    virtual ~Flow() {
        for( unsigned int i = 0; i < flow_.size(); i++) {
            buffer* b = flow_.at(i).second;
            delete b;
        }
    }
};


typedef typename std::pair<int,int> range;
typedef typename std::vector<range> vector_range;

const range NULLRANGE(0,-1);

std::string rangetos(range r) { return string_format("<%d,%d>",r.first,r.second); }

std::string vrangetos(vector_range r) {
    std::string s;
    for(unsigned int i = 0; i < r.size(); i++) {
        s += rangetos(r[i]);
        if ( ( i + 1 ) < r.size()) {
            s += ",";
        }
    }
    
    return s;
}

class baseMatch {
protected:
    std::string expr_;
public:
    virtual range match(const char* str, unsigned int max_len = 0) { return NULLRANGE; };
    virtual range match(buffer& b) {
        return match((const char*)b.data(),b.size());
    }
    
    std::string& expr() { return expr_; }
};

class simpleMatch : public baseMatch {
    range last_result_;
    std::string last_query_;
public:    
    simpleMatch(const char* e) : last_result_(NULLRANGE) { expr() = e; }
    simpleMatch(std::string& e) : last_result_(NULLRANGE) { expr() = e; }
    
    
    virtual range match(const char* str, unsigned int max_len = 0);
    virtual range search_function(std::string &expr, std::string &str) { 
        int where = str.find(expr);
        
        if (where < 0) {
            return NULLRANGE;
        } else {
            return range(where,str.size()); 
        }
    };
    
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
        
        //DIAS_("Looking in " + last_query_ + "' for '"  + expr_  + "' from " + std::to_string(from) + " size " + std::to_string(scope) + "\n");
        
        std::string tmp = last_query_.substr(from,scope);
//         int pos = tmp.find(expr_.c_str());

        range loc = search_function(expr(),tmp);
        
        //std::cout << "Found at " << pos << "\n";
        
        if(loc != NULLRANGE) {
            int pos = loc.first;
            int len = loc.second;
            
            last_result_ = range(from+pos,from+pos+len-1);
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
    
    range loc = search_function(expr(),last_query_);
    

    if(loc == NULLRANGE) {
        DEBS_("simpleMatch::match: <0,-1>");
        last_result_ = NULLRANGE;
        
    } else {
        int pos = loc.first;
        int len = loc.second;
        
        DEB_("simpleMatch::match: <%d,%d>",pos,len);
        last_result_ = range(pos,pos+len-1);
    }
    
    return last_result_;
};

template <class SourceType>
class flowMatch {
    unsigned int level;                                                        // add layer of dependency
    std::vector<std::pair<SourceType,baseMatch*>>  signature_;                // series of L/R/X matches to be satisfied

public:    
    void add(SourceType s, baseMatch* m) { 
            signature_.push_back(std::pair<SourceType,baseMatch*>(s,m));             
    };
    
    virtual std::vector<range> match(Flow<SourceType>* f) {
        
        std::vector<range> ret;
        ret.push_back(NULLRANGE);   // prepare for only partial match
        
        int flow_match_skipped = 0;
        
        int signature_last_match = -1;
        unsigned int cur_flow = 0;
        
        for( ; cur_flow < f->flow().size(); cur_flow++) {
            auto ff = f->flow().at(cur_flow);
            
            SourceType ff_src = ff.first;
            buffer*    ff_buf = ff.second; 
            
            unsigned int sig_test = signature_last_match + 1;
            
            if(sig_test >= signature_.size()) {
                // we hit the end of  the signature!
                break;
            }

          
            // FIXME: check size and boundaries
            SourceType   sig_src = signature_.at(sig_test).first;
            baseMatch* sig_match = signature_.at(sig_test).second;

            DEB_("flowMatch::match: flow %d/%d",cur_flow,f->flow().size());
            DEB_("flowMatch::match: signature[%s]: %s", std::to_string(sig_src).c_str(), sig_match->expr().c_str());
//             DIA_("flowMatch::match: pattern[%s]: %s",std::to_string(ff_src).c_str(), hex_dump(ff_buf->data(),ff_buf->size()).c_str());
            auto xxx = ff_buf->size() < 16 ? ff_buf->size() : 16;
            DEB_("flowMatch::match: pattern[%s]: %s",std::to_string(ff_src).c_str(), hex_dump(ff_buf->data(),xxx).c_str());            
            
            if ( ff_src == sig_src ) {
                range r = sig_match->match((const char*)ff_buf->data(),(unsigned int)ff_buf->size());
                DEB_("flowMatch::match: result: %s",rangetos(r).c_str());
                
                if( r != NULLRANGE) {
                    // yes! we have a (at least partial) hit
                    signature_last_match++;
                    ret.push_back(r);
                    
                    DEBS_("flowMatch::match: OK")
                }
                else {

                    DEBS_("flowMatch::match: -")
                    
                    // no this is not a hit
                    if(signature_last_match >= 0) {
                        // if we already matched, increase skipped counter
                        flow_match_skipped++;

                        DEB_("flowMatch::match: matches: %d skip counter %d",signature_last_match,flow_match_skipped)
                    }
                }
            }
            else {
                DEBS_("flowMatch::match: different direction, skipping.");
                DEBS_("flowMatch::match: different direction, skipping.");
                // this flow entry is not for us
                continue;
            }
        }
        
        if( signature_last_match == (signed int)( signature_.size() - 1 ) ) {
            
            DEBS_("flowMatch::match: fully matched!")            
            
            ret.erase(ret.begin());
            return ret;
        }
        
        DEB_("flowMatch::matched only %d/%d",signature_last_match,signature_.size())        
        return ret;
    }
};

class regexMatch : public simpleMatch {
protected:
    std::regex expr_comp_;
    
public:
    
    regexMatch(const char* e) : simpleMatch(e), expr_comp_(e) {}
    regexMatch(std::string& e) : simpleMatch(e), expr_comp_(e) {}
    
    virtual range search_function(std::string &expr, std::string &str) { 
        std::smatch m;
        auto e = std::regex(expr);
        auto r = std::regex_search ( str , m, e );
        
        DIA_("regexMatch::search_function: %s, %d matches.", r,m.size());
        
        for (unsigned i=0; i<m.size(); ++i) {
            // we need just single(first) result 
            return range(m.position(i),m.str().size());
        }
        
        return NULLRANGE;
    }
};


template <class matchType>
class SignatureType : public matchType {
public:
    std::string name;
    std::string category;
    
    unsigned int bytes_limit;
};

typedef SignatureType<flowMatch<unsigned char>> duplexSignature;
typedef Flow<unsigned char> duplexFlow;
