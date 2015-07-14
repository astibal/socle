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

#ifndef SIGNATURE_HPP
 #define SIGNATURE_HPP

#include <string>
#include <regex>
#include <vector>
#include <tuple>
#include <buffer.hpp>
#include <display.hpp>
#include <logger.hpp>
#include <ranges.hpp>

typedef std::pair<unsigned char,buffer*> side_buffer_ptr;


template <class SourceType>
class Flow {
    std::vector<std::pair<SourceType,buffer*>> flow_; // store flow data ... ala follow tcp stream :) 
                                     // Flowdata::side_ doesn't have to be necesarilly L or R
    std::vector<int> update_counters_;
                                     
public:
    std::vector<std::pair<SourceType,buffer*>>& flow() { return flow_; }
    std::vector<std::pair<SourceType,buffer*>>& operator() () { return flow(); }

    unsigned int append(SourceType src,buffer& b) { return append(src,b.data(),b.size());};
    unsigned int append(SourceType src,buffer* pb) { return append(src,pb->data(),pb->size());};
    unsigned int append(SourceType src,const void* data, size_t len) {
        if(flow_.size() == 0) {
            DIA_("New flow init: side: %c: %d bytes",src,len);
            DUM_("New flow init: side: %c: incoming  data:\n%s",src,hex_dump((unsigned char*)data,len).c_str());
            auto b = new buffer(data,len);
            // src initialized by value, buffer is pointer
            std::pair<SourceType,buffer*> t(src,b);
            flow_.push_back(t);
            update_counters_.push_back(1);
        }
        else if (flow_.back().first == src) {
            DIA_("Flow::append: to current side: %c: %d bytes",len);
            DUM_("Flow::append: to current side: %c: incoming  data:\n%s",src,hex_dump((unsigned char*)data,  len > 128 ? 128 : len ).c_str());
            flow_.back().second->append(data,len);
            int& counter_ref = update_counters_.back();
            counter_ref++;
        }
        else if (flow_.back().first != src) {
            DIA_("Flow::append: to new side: %c: %d bytes",src,len);
            DUM_("Flow::append: to new side: %c: incoming data:\n%s",src,hex_dump((unsigned char*)data,len > 128 ? 128 : len ).c_str());
            auto b = new buffer(data,len);
            // src initialized by value, buffer is pointer
            std::pair<SourceType,buffer*> t(src,b);
            flow_.push_back(t);
            update_counters_.push_back(1);
        }
        
        return len;
    };
    
    buffer* at(SourceType t, int idx) const {
        int i = 0;
        for(auto it = flow_.begin() ; it < flow_.end(); ++it) {
            SourceType tt = it->first;
            buffer* ff = it->second;
            if (tt == t) {
                if(i == idx) {
                    return ff;
                }

                i++;
            }
        }
        
        return nullptr;
    }
    
    std::string hr(bool verbose=false) {
        std::string r = string_format("0x%x: ",this);

        if(flow_.size() == 0) {
            r += "<empty>";
        }
        else
        for( unsigned int i = 0; i < flow_.size(); i++) {
            char s =  flow_.at(i).first;
            buffer* b = flow_.at(i).second;
            
            int updates = 1;
            if(i < update_counters_.size()) updates = update_counters_.at(i);
            
            r += string_format("%c:%s[%d]",s, updates == 1 ? "" : string_format("<%d>:",updates).c_str(),b->size());
            if(verbose) {
                r += string_format("\n%s\n",hex_dump(b).c_str());
            }
            
            if(i+1 != flow_.size()) {
                if(!verbose)
                    r += ", ";
            }
        }
        
        return r;
    }
    
    virtual ~Flow() {
        for( unsigned int i = 0; i < flow_.size(); i++) {
            buffer* b = flow_.at(i).second;
            delete b;
        }
    }
};


class baseMatch {
protected:
    std::string expr_;
    baseMatch(const char* e): expr_(e) {};
    baseMatch(std::string& e): expr_(e) {};
    baseMatch(const char* e, unsigned int o, unsigned int b) : expr_(e), match_limits_offset(o), match_limits_bytes(b) { expr() = e; }
    baseMatch(std::string& e, unsigned int o, unsigned int b) : expr_(e), match_limits_offset(o), match_limits_bytes(b) { expr() = e; }  
public:
    // directly accessible match constrains
    unsigned int match_limits_offset = 0;
    unsigned int match_limits_bytes = 0;
    
    virtual ~baseMatch() {}
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
    virtual ~simpleMatch() {}
    simpleMatch(const char* e) : baseMatch(e), last_result_(NULLRANGE) { }
    simpleMatch(std::string& e) : baseMatch(e), last_result_(NULLRANGE) { }
    simpleMatch(const char* e, unsigned int o, unsigned int b) : baseMatch(e,o,b),  last_result_(NULLRANGE) {}
    simpleMatch(std::string& e, unsigned int o, unsigned int b) : baseMatch(e,o,b),  last_result_(NULLRANGE) {}
    
    virtual range match(const char* str, unsigned int len = 0) {
        
        range result;
        
        auto s = std::string(str,len);
        EXT_("simpleMatch::match: '%s', len='%d' ",hex_dump((unsigned char*)s.c_str(),len).c_str(),len);
        
        range loc = search_function(expr(),s);
        

        if(loc == NULLRANGE) {
            DEBS_("simpleMatch::match: <0,-1>");
            result = NULLRANGE;
            
        } else {
            int pos = loc.first;
            int len = loc.second;
            
            DEB_("simpleMatch::match: <%d,%d>",pos,len);
            result = range(pos,pos+len-1);
        }
        
        return result;
    };
        
    virtual range search_function(std::string &expr, std::string &str) { 
        int where = str.find(expr);

        if(LEV_(DUM)) {
            DUM_("simpleMatch::search_function: \nexpr:\n%s\ndata:\n%s",expr.c_str(),hex_dump((unsigned char*)str.c_str(), str.size() > 128 ? 128 : str.size() ).c_str());
        }
        else {
            DEB_("simpleMatch::search_function: \nexpr: '%s'",expr.c_str());
        }
        
        if (where < 0) {
            return NULLRANGE;
        } else {
            return range(where,str.size()); 
        }
    };
    
    virtual range operator() () { return last_result_; }
    virtual range operator() (const char* str, unsigned int max_len = 0) { return match(str,max_len); };
};


template <class SourceType>
class flowMatch {
    
public:
    std::string& name() { return name_; }
   
protected:    
    std::string name_;                                                         
    std::vector<std::pair<SourceType,baseMatch*>>  signature_;                // series of L/R/X matches to be satisfied

public:    
    
    ~flowMatch() {
        for( typename std::vector<std::pair<SourceType,baseMatch*>>::iterator i = signature_.begin(); i != signature_.end(); i++ ) {
            auto match = (*i).second;
            
            DEB_("flowmatch::destructor: deleting signature %p",match);
//             delete match;
        }
    }
    
    void add(SourceType s, baseMatch* m) { 
            signature_.push_back(std::pair<SourceType,baseMatch*>(s,m));             
    };
    
    
    virtual vector_range match(Flow<SourceType>* f) {
        vector_range v;
        unsigned int p;
        
        bool b = match(f,v,p);
        if(b) {
            return v;
        }
        
        vector_range ff; 
        ff.push_back(NULLRANGE);
        return ff;
    }
    
    // state-aware match function - state is hold in 
    virtual bool match(Flow<SourceType>* f, vector_range& ret, unsigned int& sig_pos) {
        
        
        int flow_step = 0;
        
        // sanititze step if we have some result aready.  Step always starts at LAST already examined
        // flow, NOT NEXT. We need to check if there are new data in the last flow.
        if (ret.size() > 0) {
            flow_step = ret.size() -1;
        }
        
        unsigned int cur_flow = flow_step;
        

        DEB_("flowMatch::match: search flow from #%d/%d: %s :sig pos = %d/%d",flow_step,f->flow().size(),vrangetos(ret).c_str(),sig_pos,signature_.size());
        
        bool first_iter = true;
        SourceType last_src;
        for( ; cur_flow < f->flow().size() && sig_pos < signature_.size(); cur_flow++) {
            auto ff = f->flow().at(cur_flow);
            
            SourceType ff_src = ff.first;
            buffer*    ff_buf = ff.second; 

            // init unknown type of source
            if(first_iter) {
                first_iter = false;
                last_src = ff_src;
            }
            
            bool direction_change = false;
            if(last_src != ff_src) {
                direction_change = true;
                last_src = ff_src;
            }
         
            // check size and boundaries
            SourceType   sig_src = signature_.at(sig_pos).first;
            baseMatch* sig_match = signature_.at(sig_pos).second;
            unsigned int sig_match_limit_offset = sig_match->match_limits_offset;
            unsigned int sig_match_limit_bytes = sig_match->match_limits_bytes;
            
            // don't attempt to match empty buffer
            if(ff_buf->size() == 0) {
                continue;
            }
            
            if ( ff_src == sig_src ) {
                
                // create view which will reflect signature limits
                buffer ff_view = ff_buf->view();
                
                if(sig_match_limit_bytes > 0 || sig_match_limit_offset > 0) {
                    ff_view = ff_buf->view(
                            sig_match_limit_offset < ff_buf->size() ? sig_match_limit_offset : ff_buf->size() - 1,
                            sig_match_limit_bytes + sig_match_limit_offset < ff_buf->size() ? sig_match_limit_bytes : ff_buf->size()
                                        );
                }
                
                // DEBUGS
                DEB_("flowMatch::match: flow %d/%d : dirchange: %d",cur_flow,f->flow().size(),direction_change);
                DEB_("flowMatch::match: signature[%s]: %s", std::to_string(sig_src).c_str(), sig_match->expr().c_str());
                DEB_("flowMatch::match: pattern[%s] view-size=%d",std::to_string(ff_src).c_str(), ff_view.size());                                    
                DUM_("flowMatch::match: data=\n%s",hex_dump(ff_view.data(),ff_view.size()).c_str());
              
                range r = sig_match->match((const char*)ff_view.data(),(unsigned int)ff_view.size());
                DEB_("flowMatch::match: result: %s",rangetos(r).c_str());
                
                if( r != NULLRANGE) {

                    if(cur_flow == (ret.size() - 1)) {
                        // if previous result was NULLRANGE, remove
                        ret.erase(ret.end());
                    }
                    
                    ret.push_back(r);
                    ++sig_pos;
                    DEBS_("flowMatch::match: interim OK")
                }
                else {
                    // don't add another NULLRANGES if we are at last position which is NULLRANGE already
                    if(cur_flow != (ret.size() - 1)) {
                            ret.push_back(NULLRANGE);
                    }
                    DEBS_("flowMatch::match: interim nok");
                }
            }
            else {
                DEBS_("flowMatch::match: different direction, skipping.");
                if(cur_flow != (ret.size() - 1)) {
                        ret.push_back(NULLRANGE);
                }
            }
        }
        
        if(sig_pos >= signature_.size()) {
            
            DIAS_("flowMatch::match: fully matched!")            
            
//             ret.erase(ret.begin());
            return true;
        }
        
        if(sig_pos > 0) {
            DIA_("flowMatch::match: partial result %d/%d",sig_pos,signature_.size())        
        } else {
            DEBS_("flowMatch::match: nok");
        }
        
        return false;
    }
};

class regexMatch : public simpleMatch {
protected:
    std::regex expr_comp_;
    
public:
    
    regexMatch(const char* e) : simpleMatch(e), expr_comp_(e) {}
    regexMatch(std::string& e) : simpleMatch(e), expr_comp_(e) {}
    regexMatch(const char* e, unsigned int o, unsigned int b) : simpleMatch(e,o,b), expr_comp_(e) {}
    regexMatch(std::string& e, unsigned int o, unsigned int b) : simpleMatch(e,o,b), expr_comp_(e) {}

    
    // expr is ignored, regex is already compiled
    virtual range search_function(std::string &expr, std::string &str) { 
        std::smatch m;
        std::regex_search ( str , m, expr_comp_ );
        
        DUM_("regexMatch::search_function: \nexpr:\n%s\ndata:\n%s",expr.c_str(),hex_dump((unsigned char*)str.c_str(),str.size()).c_str());
        DEB_("regexMatch::search_function: matches %d times.", m.size());
        
        for (unsigned i=0; i<m.size(); ++i) {
            // we need just single(first) result 
            return range(m.position(i),m.str().size());
        }
        
        return NULLRANGE;
    }
};




// typedef SignatureType<flowMatch<unsigned char>> duplexSignature;
typedef Flow<char> duplexFlow;
typedef flowMatch<char> duplexFlowMatch;


class flowMatchState {
protected:
    bool         hit_ = false;    
    vector_range ranges_;
    unsigned int sig_pos_ = 0;
    
public:
    bool& hit() { return hit_; }
    vector_range& result() { return ranges_; };
    
    bool update(duplexFlow* f, duplexFlowMatch* signature) {
       return signature->match(f,ranges_,sig_pos_);
    }
};

#endif