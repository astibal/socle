
#include <traflog/traflog.hpp>

namespace socle::traflog {


    std::string traflog_dir_key(baseProxy* proxy_) {
        std::string lh;
        if(! proxy_->ls().empty()) {
            lh = proxy_->ls().at(0)->host();
        }
        else {
            if(! proxy_->lda().empty()) {
                lh = proxy_->lda().at(0)->host();
            }
        }
        return lh;
    }

    std::string traflog_file_key(baseProxy* proxy_, char side) {

        if(! proxy_ ) {
            return "";
        }

        std::string l;
        if(! proxy_->ls().empty() ) {
            l = proxy_->ls().at(0)->name();
        }
        else {
            if(! proxy_->lda().empty()) {
                l = proxy_->lda().at(0)->name();
            }
        }

        std::string r;
        if(! proxy_->rs().empty()) {
            r = proxy_->rs().at(0)->name();
        }
        else {
            if( ! proxy_->rda().empty()) {
                r = proxy_->rda().at(0)->name();
            }
        }



        if (side == 'L' || side == 'l') {

            if (proxy_->lsize() > 0 && proxy_->rsize() > 0 ) {
                return string_format("%s-%s",l.c_str(),r.c_str());
            }
            else if (proxy_->lsize() > 0) {
                return string_format("%s-%s",l.c_str(),"unknown");
            }
            else if (proxy_->rsize() > 0) {
                return string_format("%s-%s","unknown",r.c_str());
            }
            else {
                return std::string("unknown-unknown");
            }
        } else {
            if (proxy_->lsize() > 0 && proxy_->rsize() > 0 ) {
                return string_format("%s-%s",r.c_str(),l.c_str());
            }
            else if (proxy_->rsize() > 0) {
                return string_format("%s-%s",r.c_str(),"unknown");
            }
            else if (proxy_->lsize() > 0) {
                return string_format("%s-%s","unknown",l.c_str());
            }
            else {
                return std::string("unknown-unknown");
            }
        }
    }


}
