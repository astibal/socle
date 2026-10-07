#include <gtest/gtest.h>
#include <sslcom.hpp>
#include <sslmitmcom.hpp>
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <memory>
#include <sys/socket.h>
#include <unistd.h>

std::string FILE_to_string(FILE* file);
bool fullchain_file_exists(std::string_view filename);
std::optional<CertificateChainCtx> load_cert_pair(
    std::string_view key, std::string_view certificate, const char* password);
int add_ext(STACK_OF(X509_EXTENSION)* extensions, int nid, char* value);

namespace {

std::unique_ptr<X509, decltype(&X509_free)> load_tls_test_certificate() {
    FILE* file = std::fopen("etc/certs/default/srv-cert.pem", "r");
    if (!file)
        return {nullptr, X509_free};
    X509* certificate = PEM_read_X509(file, nullptr, nullptr, nullptr);
    std::fclose(file);
    return {certificate, X509_free};
}

TEST(TLS_Tests, CertificateFileAndExtensionHelpersCoverSuccessAndFailure) {
    EXPECT_TRUE(FILE_to_string(nullptr).empty());
    FILE* certificate_file = std::fopen("etc/certs/default/srv-cert.pem", "r");
    ASSERT_NE(certificate_file, nullptr);
    const std::string pem = FILE_to_string(certificate_file);
    EXPECT_NE(pem.find("BEGIN CERTIFICATE"), std::string::npos);
    EXPECT_EQ(std::fgetc(certificate_file), '-'); // helper rewinds its input
    std::fclose(certificate_file);

    EXPECT_TRUE(fullchain_file_exists("etc/certs/default/srv-cert.pem"));
    EXPECT_FALSE(fullchain_file_exists("/definitely/missing/fullchain.pem"));
    EXPECT_FALSE(load_cert_pair("etc/certs/default/srv-key.pem",
                                "/definitely/missing/cert.pem", nullptr).has_value());
    EXPECT_FALSE(load_cert_pair("/definitely/missing/key.pem",
                                "etc/certs/default/srv-cert.pem", nullptr).has_value());
    auto pair = load_cert_pair("etc/certs/default/srv-key.pem",
                               "etc/certs/default/srv-cert.pem", nullptr);
    ASSERT_TRUE(pair.has_value());
    EXPECT_NE(pair->chain.key, nullptr);
    EXPECT_NE(pair->chain.cert, nullptr);
    pair->release();

    char valid_san[] = "DNS:helper.example";
    char invalid_value[] = "not-a-valid-san";
    EXPECT_EQ(add_ext(nullptr, NID_subject_alt_name, valid_san), 0);
    EXPECT_EQ(add_ext(nullptr, NID_subject_alt_name, invalid_value), 0);
    auto* extensions = sk_X509_EXTENSION_new_null();
    ASSERT_NE(extensions, nullptr);
    EXPECT_EQ(add_ext(extensions, NID_subject_alt_name, valid_san), 1);
    EXPECT_EQ(sk_X509_EXTENSION_num(extensions), 1);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
}

std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> load_tls_test_key() {
    FILE* file = std::fopen("etc/certs/default/srv-key.pem", "r");
    if (!file)
        return {nullptr, EVP_PKEY_free};
    EVP_PKEY* key = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    std::fclose(file);
    return {key, EVP_PKEY_free};
}

std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> make_rsa_key() {
    EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    EVP_PKEY* key = nullptr;
    if (!context || EVP_PKEY_keygen_init(context) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(context, 2048) <= 0 ||
        EVP_PKEY_keygen(context, &key) <= 0) {
        EVP_PKEY_free(key);
        key = nullptr;
    }
    EVP_PKEY_CTX_free(context);
    return {key, EVP_PKEY_free};
}

std::unique_ptr<X509, decltype(&X509_free)> make_certificate(
    EVP_PKEY* key, long serial, const char* common_name,
    X509* issuer = nullptr, EVP_PKEY* issuer_key = nullptr) {
    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
    if (!certificate || X509_set_version(certificate.get(), 2) != 1 ||
        ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) != 1 ||
        !X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60) ||
        !X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600) ||
        X509_set_pubkey(certificate.get(), key) != 1)
        return {nullptr, X509_free};

    X509_NAME* subject = X509_get_subject_name(certificate.get());
    if (!subject || X509_NAME_add_entry_by_txt(
            subject, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0) != 1 ||
        X509_set_issuer_name(certificate.get(), issuer ? X509_get_subject_name(issuer)
                                                      : subject) != 1)
        return {nullptr, X509_free};

    if (!issuer) {
        X509_EXTENSION* extension = X509V3_EXT_conf_nid(
            nullptr, nullptr, NID_basic_constraints,
            const_cast<char*>("critical,CA:TRUE"));
        if (!extension || X509_add_ext(certificate.get(), extension, -1) != 1) {
            X509_EXTENSION_free(extension);
            return {nullptr, X509_free};
        }
        X509_EXTENSION_free(extension);
    }
    if (X509_sign(certificate.get(), issuer_key ? issuer_key : key, EVP_sha256()) <= 0)
        return {nullptr, X509_free};
    return certificate;
}

std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> make_test_crl(
    X509* issuer, EVP_PKEY* issuer_key, X509* revoked_certificate = nullptr,
    long last_update_offset = -60, long next_update_offset = 3600,
    bool omit_next_update = false) {
    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> crl(X509_CRL_new(), X509_CRL_free);
    if (!crl || X509_CRL_set_version(crl.get(), 1) != 1 ||
        X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(issuer)) != 1)
        return {nullptr, X509_CRL_free};

    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> last(ASN1_TIME_new(), ASN1_TIME_free);
    std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> next(ASN1_TIME_new(), ASN1_TIME_free);
    if (!last || !next || !X509_gmtime_adj(last.get(), last_update_offset) ||
        (!omit_next_update &&
         !X509_gmtime_adj(next.get(), next_update_offset)) ||
        X509_CRL_set1_lastUpdate(crl.get(), last.get()) != 1 ||
        (!omit_next_update &&
         X509_CRL_set1_nextUpdate(crl.get(), next.get()) != 1))
        return {nullptr, X509_CRL_free};

    if (revoked_certificate) {
        X509_REVOKED* entry = X509_REVOKED_new();
        std::unique_ptr<ASN1_TIME, decltype(&ASN1_TIME_free)> when(
            ASN1_TIME_new(), ASN1_TIME_free);
        if (!entry || !when || !X509_gmtime_adj(when.get(), -30) ||
            X509_REVOKED_set_serialNumber(
                entry, X509_get_serialNumber(revoked_certificate)) != 1 ||
            X509_REVOKED_set_revocationDate(entry, when.get()) != 1 ||
            X509_CRL_add0_revoked(crl.get(), entry) != 1) {
            X509_REVOKED_free(entry);
            return {nullptr, X509_CRL_free};
        }
    }
    if (X509_CRL_sort(crl.get()) != 1 ||
        X509_CRL_sign(crl.get(), issuer_key, EVP_sha256()) <= 0)
        return {nullptr, X509_CRL_free};
    return crl;
}

TEST(TLS_Tests, CrlLoadersAcceptDerAndPemWithoutPollutingErrors) {
    auto issuer_key = make_rsa_key();
    auto issuer = make_certificate(issuer_key.get(), 9, "CRL loader CA");
    auto crl = make_test_crl(issuer.get(), issuer_key.get());
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(crl, nullptr);

    unsigned char* der_data = nullptr;
    const int der_size = i2d_X509_CRL(crl.get(), &der_data);
    ASSERT_GT(der_size, 0);
    ASSERT_NE(der_data, nullptr);
    auto free_der = raw::guard([&] { OPENSSL_free(der_data); });
    buffer der;
    der.append(reinterpret_cast<const char*>(der_data), der_size);
    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> parsed_der(
        inet::crl::crl_from_bytes(der), X509_CRL_free);
    ASSERT_NE(parsed_der, nullptr);
    EXPECT_EQ(X509_CRL_verify(parsed_der.get(), issuer_key.get()), 1);

    buffer der_with_trailing_data;
    der_with_trailing_data.append(
        reinterpret_cast<const char*>(der_data), der_size);
    const unsigned char trailing_byte = 0x00;
    der_with_trailing_data.append(&trailing_byte, 1);
    EXPECT_EQ(inet::crl::crl_from_bytes(der_with_trailing_data), nullptr);
    EXPECT_EQ(ERR_peek_error(), 0U);

    std::unique_ptr<BIO, decltype(&BIO_free)> pem_bio(
        BIO_new(BIO_s_mem()), BIO_free);
    ASSERT_NE(pem_bio, nullptr);
    ASSERT_EQ(PEM_write_bio_X509_CRL(pem_bio.get(), crl.get()), 1);
    char* pem_data = nullptr;
    const long pem_size = BIO_get_mem_data(pem_bio.get(), &pem_data);
    ASSERT_GT(pem_size, 0);
    ASSERT_NE(pem_data, nullptr);
    const std::string pem(pem_data, static_cast<std::size_t>(pem_size));
    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> parsed_pem(
        inet::crl::crl_from_bytes(pem.c_str()), X509_CRL_free);
    ASSERT_NE(parsed_pem, nullptr);
    EXPECT_EQ(X509_CRL_verify(parsed_pem.get(), issuer_key.get()), 1);
    const std::string pem_with_trailing_data = pem + "not part of the CRL";
    EXPECT_EQ(inet::crl::crl_from_bytes(pem_with_trailing_data.c_str()), nullptr);
    EXPECT_EQ(ERR_peek_error(), 0U);

    const auto pem_path = std::filesystem::temp_directory_path() /
        ("smithproxy-crl-loader-" + std::to_string(::getpid()) + ".pem");
    FILE* output = std::fopen(pem_path.c_str(), "w");
    ASSERT_NE(output, nullptr);
    ASSERT_EQ(PEM_write_X509_CRL(output, crl.get()), 1);
    std::fclose(output);
    auto remove_pem = raw::guard([&] { std::filesystem::remove(pem_path); });
    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> parsed_file(
        inet::crl::crl_from_file(pem_path.c_str()), X509_CRL_free);
    ASSERT_NE(parsed_file, nullptr);
    EXPECT_EQ(X509_CRL_verify(parsed_file.get(), issuer_key.get()), 1);
    output = std::fopen(pem_path.c_str(), "a");
    ASSERT_NE(output, nullptr);
    ASSERT_GE(std::fputs("not part of the CRL", output), 0);
    std::fclose(output);
    EXPECT_EQ(inet::crl::crl_from_file(pem_path.c_str()), nullptr);
    EXPECT_EQ(ERR_peek_error(), 0U);

    EXPECT_EQ(inet::crl::crl_from_bytes("not a CRL"), nullptr);
    EXPECT_EQ(ERR_peek_error(), 0U);
}

bool add_certificate_extension(X509* certificate, int nid, const char* value) {
    X509_EXTENSION* extension = X509V3_EXT_conf_nid(
        nullptr, nullptr, nid, const_cast<char*>(value));
    if (!extension)
        return false;
    const bool added = X509_add_ext(certificate, extension, -1) == 1;
    X509_EXTENSION_free(extension);
    return added;
}

std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)> make_ocsp_response(
    X509* certificate, X509* issuer, EVP_PKEY* signing_key, int status,
    long this_update_offset = -60, long next_update_offset = 3600,
    X509* signer = nullptr, int duplicate_status = -1,
    bool omit_next_update = false) {
    OCSP_CERTID* id = OCSP_cert_to_id(EVP_sha256(), certificate, issuer);
    OCSP_BASICRESP* basic = OCSP_BASICRESP_new();
    ASN1_TIME* this_update = ASN1_TIME_set(nullptr, std::time(nullptr) + this_update_offset);
    ASN1_TIME* next_update = omit_next_update ? nullptr
        : ASN1_TIME_set(nullptr, std::time(nullptr) + next_update_offset);
    ASN1_TIME* revoked_at = status == V_OCSP_CERTSTATUS_REVOKED
        ? ASN1_TIME_set(nullptr, std::time(nullptr) - 120) : nullptr;
    ASN1_TIME* duplicate_revoked_at = duplicate_status == V_OCSP_CERTSTATUS_REVOKED
        ? ASN1_TIME_set(nullptr, std::time(nullptr) - 120) : nullptr;
    if (!id || !basic || !this_update || (!omit_next_update && !next_update) ||
        (status == V_OCSP_CERTSTATUS_REVOKED && !revoked_at) ||
        (duplicate_status == V_OCSP_CERTSTATUS_REVOKED && !duplicate_revoked_at) ||
        !OCSP_basic_add1_status(basic, id, status, 0, revoked_at,
                                this_update, next_update) ||
        (duplicate_status >= 0 && !OCSP_basic_add1_status(
            basic, id, duplicate_status, 0, duplicate_revoked_at,
            this_update, next_update)) ||
        OCSP_basic_sign(basic, signer ? signer : issuer, signing_key,
                        EVP_sha256(), nullptr, 0) != 1) {
        OCSP_CERTID_free(id);
        OCSP_BASICRESP_free(basic);
        ASN1_TIME_free(this_update);
        ASN1_TIME_free(next_update);
        ASN1_TIME_free(revoked_at);
        ASN1_TIME_free(duplicate_revoked_at);
        return {nullptr, OCSP_RESPONSE_free};
    }
    OCSP_RESPONSE* response = OCSP_response_create(
        OCSP_RESPONSE_STATUS_SUCCESSFUL, basic);
    OCSP_CERTID_free(id);
    OCSP_BASICRESP_free(basic);
    ASN1_TIME_free(this_update);
    ASN1_TIME_free(next_update);
    ASN1_TIME_free(revoked_at);
    ASN1_TIME_free(duplicate_revoked_at);
    return {response, OCSP_RESPONSE_free};
}

}

TEST(TLS_Tests, CrlValidationDistinguishesCurrentAndRevokedCertificates) {
    auto issuer_key = make_rsa_key();
    auto leaf_key = make_rsa_key();
    auto issuer = make_certificate(issuer_key.get(), 1, "Current test CA");
    auto leaf = make_certificate(leaf_key.get(), 2, "Current test leaf",
                                 issuer.get(), issuer_key.get());
    ASSERT_NE(leaf, nullptr);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(issuer_key, nullptr);

    auto current = make_test_crl(issuer.get(), issuer_key.get());
    auto revoked = make_test_crl(issuer.get(), issuer_key.get(), leaf.get());
    auto recent_without_next_update = make_test_crl(
        issuer.get(), issuer_key.get(), nullptr, -60, 0, true);
    auto stale_without_next_update = make_test_crl(
        issuer.get(), issuer_key.get(), nullptr, -172800, 0, true);
    auto unsupported_delta = make_test_crl(
        issuer.get(), issuer_key.get());
    ASSERT_NE(current, nullptr);
    ASSERT_NE(revoked, nullptr);
    ASSERT_NE(recent_without_next_update, nullptr);
    ASSERT_NE(stale_without_next_update, nullptr);
    ASSERT_NE(unsupported_delta, nullptr);

    std::unique_ptr<ASN1_INTEGER, decltype(&ASN1_INTEGER_free)> delta_base(
        ASN1_INTEGER_new(), ASN1_INTEGER_free);
    ASSERT_NE(delta_base, nullptr);
    ASSERT_EQ(ASN1_INTEGER_set(delta_base.get(), 1), 1);
    X509_EXTENSION* delta_extension = X509V3_EXT_i2d(
        NID_delta_crl, 1, delta_base.get());
    ASSERT_NE(delta_extension, nullptr);
    ASSERT_EQ(X509_CRL_add_ext(
                  unsupported_delta.get(), delta_extension, -1), 1);
    X509_EXTENSION_free(delta_extension);
    ASSERT_GT(X509_CRL_sign(
                  unsupported_delta.get(), issuer_key.get(), EVP_sha256()), 0);

    EXPECT_EQ(inet::crl::crl_is_revoked_by(leaf.get(), issuer.get(), current.get()), 0);
    EXPECT_EQ(inet::crl::crl_is_revoked_by(leaf.get(), issuer.get(), revoked.get()), 1);
    const std::filesystem::path ca_file = std::filesystem::temp_directory_path()
        / ("smithproxy-current-test-ca-" + std::to_string(::getpid()) + ".pem");
    FILE* output = std::fopen(ca_file.c_str(), "w");
    ASSERT_NE(output, nullptr);
    ASSERT_EQ(PEM_write_X509(output, issuer.get()), 1);
    std::fclose(output);
    auto remove_ca = raw::guard([&] { std::filesystem::remove(ca_file); });

    EXPECT_EQ(inet::crl::crl_verify_trust(
                  leaf.get(), issuer.get(), current.get(), ca_file.string()), 1);
    EXPECT_EQ(inet::crl::crl_verify_trust(
                  leaf.get(), issuer.get(), revoked.get(), ca_file.string()), 1);
    EXPECT_EQ(inet::crl::crl_verify_trust(
                  leaf.get(), issuer.get(), recent_without_next_update.get(),
                  ca_file.string()),
              1);
    EXPECT_EQ(inet::crl::crl_verify_trust(
                  leaf.get(), issuer.get(), stale_without_next_update.get(),
                  ca_file.string()),
              0);
    EXPECT_EQ(inet::crl::crl_verify_trust(
                  leaf.get(), issuer.get(), unsupported_delta.get(),
                  ca_file.string()),
              0);

    const std::filesystem::path ca_directory =
        std::filesystem::temp_directory_path() /
        ("smithproxy-current-test-ca-path-" + std::to_string(::getpid()));
    std::filesystem::remove_all(ca_directory);
    std::filesystem::create_directories(ca_directory);
    auto remove_ca_directory = raw::guard(
        [&] { std::filesystem::remove_all(ca_directory); });
    char hashed_name[32] {};
    std::snprintf(hashed_name, sizeof(hashed_name), "%08lx.0",
                  X509_NAME_hash(X509_get_subject_name(issuer.get())));
    const auto hashed_ca_file = ca_directory / hashed_name;
    output = std::fopen(hashed_ca_file.c_str(), "w");
    ASSERT_NE(output, nullptr);
    ASSERT_EQ(PEM_write_X509(output, issuer.get()), 1);
    std::fclose(output);

    EXPECT_EQ(inet::crl::crl_verify_trust(
                  leaf.get(), issuer.get(), current.get(), ca_directory.string()), 1);
    EXPECT_EQ(inet::crl::crl_verify_trust(
                  leaf.get(), issuer.get(), revoked.get(), ca_directory.string()), 1);
}

TEST(TLS_Tests, CrlVerificationUsesConfiguredCaBundleWhenPathIsEmpty) {
    auto issuer_key = make_rsa_key();
    auto leaf_key = make_rsa_key();
    auto issuer = make_certificate(issuer_key.get(), 41, "Private CRL test CA");
    auto leaf = make_certificate(leaf_key.get(), 42, "Private CRL test leaf",
                                 issuer.get(), issuer_key.get());
    auto crl = make_test_crl(issuer.get(), issuer_key.get());
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(leaf, nullptr);
    ASSERT_NE(crl, nullptr);

    const std::filesystem::path ca_file = std::filesystem::temp_directory_path()
        / ("smithproxy-private-crl-ca-" + std::to_string(::getpid()) + ".pem");
    FILE* output = std::fopen(ca_file.c_str(), "w");
    ASSERT_NE(output, nullptr);
    ASSERT_EQ(PEM_write_X509(output, issuer.get()), 1);
    std::fclose(output);
    auto remove_ca = raw::guard([&] { std::filesystem::remove(ca_file); });

    auto& factory = SSLFactory::factory();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    factory.ca_file() = ca_file.string();
    factory.ca_path().clear();
    auto restore_factory = raw::guard([&] {
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
    });

    EXPECT_EQ(inet::crl::crl_verify_trust(
                  leaf.get(), issuer.get(), crl.get(), {}),
              1);

    const std::string invalid_location(5000, 'x');
    EXPECT_NO_THROW({
        EXPECT_EQ(inet::crl::crl_verify_trust(
                      leaf.get(), issuer.get(), crl.get(), invalid_location),
                  0);
    });

    ERR_clear_error();
    EXPECT_EQ(inet::crl::crl_verify_trust(
                  leaf.get(), issuer.get(), crl.get(),
                  (ca_file.string() + ".missing")),
              0);
    EXPECT_EQ(ERR_peek_error(), 0UL);
}

TEST(TLS_Tests, RevocationEndpointsAndOcspRequestUseCertificateExtensions) {
    auto issuer_key = make_rsa_key();
    auto leaf_key = make_rsa_key();
    auto issuer = make_certificate(issuer_key.get(), 11, "Endpoint test CA");
    auto leaf = make_certificate(leaf_key.get(), 12, "Endpoint test leaf",
                                 issuer.get(), issuer_key.get());
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(leaf, nullptr);
    ASSERT_TRUE(add_certificate_extension(
        leaf.get(), NID_crl_distribution_points,
        "URI:http://crl.example.test/root.crl"));
    ASSERT_TRUE(add_certificate_extension(
        leaf.get(), NID_info_access,
        "OCSP;URI:http://ocsp.example.test/status,"
        "caIssuers;URI:http://ca.example.test/issuer.pem"));

    EXPECT_EQ(inet::crl::crl_urls(leaf.get()),
              std::vector<std::string>({"http://crl.example.test/root.crl"}));
    EXPECT_EQ(inet::ocsp::ocsp_urls(leaf.get()),
              std::vector<std::string>({"http://ocsp.example.test/status"}));

    auto relative_leaf = make_certificate(
        leaf_key.get(), 13, "Relative CRL name leaf",
        issuer.get(), issuer_key.get());
    ASSERT_NE(relative_leaf, nullptr);
    CRL_DIST_POINTS* points = sk_DIST_POINT_new_null();
    DIST_POINT* point = DIST_POINT_new();
    ASSERT_NE(points, nullptr);
    ASSERT_NE(point, nullptr);
    point->distpoint = DIST_POINT_NAME_new();
    ASSERT_NE(point->distpoint, nullptr);
    point->distpoint->type = 1;
    point->distpoint->name.relativename = sk_X509_NAME_ENTRY_new_null();
    ASSERT_NE(point->distpoint->name.relativename, nullptr);
    const unsigned char relative_name[] = "not-a-download-url.example";
    X509_NAME_ENTRY* entry = X509_NAME_ENTRY_create_by_txt(
        nullptr, "CN", MBSTRING_ASC, relative_name, -1);
    ASSERT_NE(entry, nullptr);
    ASSERT_EQ(sk_X509_NAME_ENTRY_push(
                  point->distpoint->name.relativename, entry), 1);
    ASSERT_EQ(sk_DIST_POINT_push(points, point), 1);
    ASSERT_EQ(X509_add1_ext_i2d(
                  relative_leaf.get(), NID_crl_distribution_points,
                  points, 0, X509V3_ADD_APPEND), 1);
    CRL_DIST_POINTS_free(points);
    EXPECT_TRUE(inet::crl::crl_urls(relative_leaf.get()).empty());

    auto nul_leaf = make_certificate(
        leaf_key.get(), 14, "NUL CRL URI leaf",
        issuer.get(), issuer_key.get());
    ASSERT_NE(nul_leaf, nullptr);
    points = sk_DIST_POINT_new_null();
    point = DIST_POINT_new();
    ASSERT_NE(points, nullptr);
    ASSERT_NE(point, nullptr);
    point->distpoint = DIST_POINT_NAME_new();
    ASSERT_NE(point->distpoint, nullptr);
    point->distpoint->type = 0;
    point->distpoint->name.fullname = sk_GENERAL_NAME_new_null();
    ASSERT_NE(point->distpoint->name.fullname, nullptr);
    GENERAL_NAME* uri_name = GENERAL_NAME_new();
    ASSERT_NE(uri_name, nullptr);
    uri_name->type = GEN_URI;
    uri_name->d.uniformResourceIdentifier = ASN1_IA5STRING_new();
    ASSERT_NE(uri_name->d.uniformResourceIdentifier, nullptr);
    const unsigned char nul_uri[] =
        {'h','t','t','p',':','/','/','c','r','l','.','e','x','a','m','p','l','e',
         '\0','.','i','n','v','a','l','i','d'};
    ASSERT_EQ(ASN1_STRING_set(
                  uri_name->d.uniformResourceIdentifier,
                  nul_uri, sizeof(nul_uri)), 1);
    ASSERT_EQ(sk_GENERAL_NAME_push(
                  point->distpoint->name.fullname, uri_name), 1);
    ASSERT_EQ(sk_DIST_POINT_push(points, point), 1);
    ASSERT_EQ(X509_add1_ext_i2d(
                  nul_leaf.get(), NID_crl_distribution_points,
                  points, 0, X509V3_ADD_APPEND), 1);
    CRL_DIST_POINTS_free(points);
    EXPECT_TRUE(inet::crl::crl_urls(nul_leaf.get()).empty());

    auto nul_ocsp_leaf = make_certificate(
        leaf_key.get(), 15, "NUL OCSP URI leaf",
        issuer.get(), issuer_key.get());
    ASSERT_NE(nul_ocsp_leaf, nullptr);
    AUTHORITY_INFO_ACCESS* access = sk_ACCESS_DESCRIPTION_new_null();
    ACCESS_DESCRIPTION* description = ACCESS_DESCRIPTION_new();
    ASSERT_NE(access, nullptr);
    ASSERT_NE(description, nullptr);
    description->method = OBJ_dup(OBJ_nid2obj(NID_ad_OCSP));
    description->location = GENERAL_NAME_new();
    ASSERT_NE(description->method, nullptr);
    ASSERT_NE(description->location, nullptr);
    description->location->type = GEN_URI;
    description->location->d.uniformResourceIdentifier = ASN1_IA5STRING_new();
    ASSERT_NE(description->location->d.uniformResourceIdentifier, nullptr);
    const unsigned char nul_ocsp_uri[] =
        {'h','t','t','p',':','/','/','o','c','s','p','.','e','x','a','m','p','l','e',
         '\0','.','i','n','v','a','l','i','d'};
    ASSERT_EQ(ASN1_STRING_set(
                  description->location->d.uniformResourceIdentifier,
                  nul_ocsp_uri, sizeof(nul_ocsp_uri)), 1);
    ASSERT_EQ(sk_ACCESS_DESCRIPTION_push(access, description), 1);
    ASSERT_EQ(X509_add1_ext_i2d(
                  nul_ocsp_leaf.get(), NID_info_access,
                  access, 0, X509V3_ADD_APPEND), 1);
    AUTHORITY_INFO_ACCESS_free(access);
    EXPECT_TRUE(inet::ocsp::ocsp_urls(nul_ocsp_leaf.get()).empty());

    OCSP_REQUEST* request = nullptr;
    STACK_OF(OCSP_CERTID)* ids = sk_OCSP_CERTID_new_null();
    ASSERT_NE(ids, nullptr);
    ASSERT_EQ(inet::ocsp::ocsp_prepare_request(
                  &request, leaf.get(), EVP_sha256(), issuer.get(), ids), 1);
    ASSERT_NE(request, nullptr);
    EXPECT_EQ(sk_OCSP_CERTID_num(ids), 1);
    EXPECT_EQ(OCSP_request_onereq_count(request), 1);
    OCSP_REQUEST_free(request);
    sk_OCSP_CERTID_free(ids);
}

TEST(TLS_Tests, SignedOcspResponsesDistinguishGoodRevokedAndInvalidEvidence) {
    auto issuer_key = make_rsa_key();
    auto unrelated_key = make_rsa_key();
    auto leaf_key = make_rsa_key();
    auto issuer = make_certificate(issuer_key.get(), 21, "OCSP test CA");
    auto unrelated = make_certificate(unrelated_key.get(), 23, "Unrelated OCSP signer");
    auto leaf = make_certificate(leaf_key.get(), 22, "OCSP test leaf",
                                 issuer.get(), issuer_key.get());
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(leaf, nullptr);
    ASSERT_NE(unrelated, nullptr);

    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(
        X509_STORE_new(), X509_STORE_free);
    ASSERT_NE(store, nullptr);
    ASSERT_EQ(X509_STORE_add_cert(store.get(), issuer.get()), 1);

    auto good = make_ocsp_response(leaf.get(), issuer.get(), issuer_key.get(),
                                   V_OCSP_CERTSTATUS_GOOD);
    auto revoked = make_ocsp_response(leaf.get(), issuer.get(), issuer_key.get(),
                                      V_OCSP_CERTSTATUS_REVOKED);
    auto stale = make_ocsp_response(leaf.get(), issuer.get(), issuer_key.get(),
                                    V_OCSP_CERTSTATUS_GOOD, -7200, -3600);
    auto invalid_signature = make_ocsp_response(
        leaf.get(), issuer.get(), unrelated_key.get(), V_OCSP_CERTSTATUS_GOOD,
        -60, 3600, unrelated.get());
    auto contradictory = make_ocsp_response(
        leaf.get(), issuer.get(), issuer_key.get(), V_OCSP_CERTSTATUS_GOOD,
        -60, 3600, nullptr, V_OCSP_CERTSTATUS_REVOKED);
    auto recent_without_next_update = make_ocsp_response(
        leaf.get(), issuer.get(), issuer_key.get(), V_OCSP_CERTSTATUS_GOOD,
        -60, 0, nullptr, -1, true);
    auto stale_without_next_update = make_ocsp_response(
        leaf.get(), issuer.get(), issuer_key.get(), V_OCSP_CERTSTATUS_GOOD,
        -7200, 0, nullptr, -1, true);
    std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)> retry_later(
        OCSP_response_create(OCSP_RESPONSE_STATUS_TRYLATER, nullptr),
        OCSP_RESPONSE_free);
    ASSERT_NE(good, nullptr);
    ASSERT_NE(revoked, nullptr);
    ASSERT_NE(stale, nullptr);
    ASSERT_NE(invalid_signature, nullptr);
    ASSERT_NE(contradictory, nullptr);
    ASSERT_NE(recent_without_next_update, nullptr);
    ASSERT_NE(stale_without_next_update, nullptr);
    ASSERT_NE(retry_later, nullptr);

    const auto good_status = inet::ocsp::ocsp_verify_response(
        good.get(), leaf.get(), issuer.get(), store.get());
    EXPECT_EQ(good_status.revoked, 0);
    EXPECT_GT(good_status.ttl, 0);
    EXPECT_LE(good_status.ttl, SSLFactory::options::ocsp_status_ttl);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  revoked.get(), leaf.get(), issuer.get(), store.get()).revoked, 1);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  stale.get(), leaf.get(), issuer.get(), store.get()).revoked, -1);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  invalid_signature.get(), leaf.get(), issuer.get(), store.get()).revoked,
              -1);
    EXPECT_EQ(ERR_peek_error(), 0U);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  contradictory.get(), leaf.get(), issuer.get(), store.get()).revoked,
              -1);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  recent_without_next_update.get(), leaf.get(), issuer.get(),
                  store.get()).revoked,
              0);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  stale_without_next_update.get(), leaf.get(), issuer.get(),
                  store.get()).revoked,
              -1);
    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  retry_later.get(), leaf.get(), issuer.get(), store.get()).revoked,
              -1);
}

TEST(TLS_Tests, OcspVerificationDefaultsToConfiguredCentralTrustStore) {
    auto issuer_key = make_rsa_key();
    auto leaf_key = make_rsa_key();
    auto issuer = make_certificate(issuer_key.get(), 31, "Private OCSP test CA");
    auto leaf = make_certificate(leaf_key.get(), 32, "Private OCSP test leaf",
                                 issuer.get(), issuer_key.get());
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(leaf, nullptr);

    auto response = make_ocsp_response(
        leaf.get(), issuer.get(), issuer_key.get(), V_OCSP_CERTSTATUS_GOOD);
    ASSERT_NE(response, nullptr);

    const std::filesystem::path ca_file = std::filesystem::temp_directory_path()
        / ("smithproxy-private-ocsp-ca-" + std::to_string(::getpid()) + ".pem");
    FILE* output = std::fopen(ca_file.c_str(), "w");
    ASSERT_NE(output, nullptr);
    ASSERT_EQ(PEM_write_X509(output, issuer.get()), 1);
    std::fclose(output);
    auto remove_ca = raw::guard([&] { std::filesystem::remove(ca_file); });

    auto& factory = SSLFactory::factory();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    factory.destroy();
    factory.ca_file() = ca_file.string();
    factory.ca_path().clear();
    auto restore_factory = raw::guard([&] {
        factory.destroy();
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
    });
    ASSERT_TRUE(factory.load_trust_store());

    EXPECT_EQ(inet::ocsp::ocsp_verify_response(
                  response.get(), leaf.get(), issuer.get()).revoked,
              0);
}

TEST(TLS_Tests, CertificateStoreUtilitiesAndCacheHandleValidAndMissingInputs) {
    auto certificate = load_tls_test_certificate();
    auto key = load_tls_test_key();
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(key, nullptr);

    EXPECT_TRUE(SSLFactory::print_cn(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_issuer(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_not_before(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_not_after(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_cert(nullptr).empty());
    EXPECT_TRUE(SSLFactory::fingerprint(nullptr).empty());
    EXPECT_TRUE(SSLFactory::get_sans(nullptr).empty());
    EXPECT_TRUE(SSLFactory::print_ASN1_OCTET_STRING(nullptr).empty());

    EXPECT_EQ(SSLFactory::print_cn(certificate.get()), "Smithproxy Server Certificate");
    EXPECT_EQ(SSLFactory::print_issuer(certificate.get()), "Smithproxy Root CA");
    EXPECT_FALSE(SSLFactory::print_not_before(certificate.get()).empty());
    EXPECT_FALSE(SSLFactory::print_not_after(certificate.get()).empty());
    EXPECT_NE(SSLFactory::print_cert(certificate.get(), 2, true).find("Common Name"),
              std::string::npos);
    EXPECT_EQ(SSLFactory::fingerprint(certificate.get()).size(), 40U);
    EXPECT_EQ(SSLFactory::get_sans(certificate.get()),
              std::vector<std::string>({"DNS:Smithproxy-Server-Certificate"}));
    EXPECT_EQ(SSLFactory::get_sans_csv(certificate.get()),
              "DNS:Smithproxy-Server-Certificate");
    X509_EXTENSION* ip_sans = X509V3_EXT_conf_nid(
        nullptr, nullptr, NID_subject_alt_name,
        const_cast<char*>("IP:192.0.2.8,IP:2001:db8::8"));
    ASSERT_NE(ip_sans, nullptr);
    ASSERT_EQ(X509_add_ext(certificate.get(), ip_sans, -1), 1);
    X509_EXTENSION_free(ip_sans);
    const auto sans_with_ips = SSLFactory::get_sans(certificate.get());
    EXPECT_NE(std::find(sans_with_ips.begin(), sans_with_ips.end(), "IP:192.0.2.8"),
              sans_with_ips.end());
    EXPECT_NE(std::find(sans_with_ips.begin(), sans_with_ips.end(), "IP:2001:db8::8"),
              sans_with_ips.end());

    char time_text[128] {};
    EXPECT_EQ(SSLFactory::convert_ASN1TIME(X509_get0_notBefore(certificate.get()),
                                          time_text, sizeof(time_text)), EXIT_SUCCESS);
    EXPECT_NE(time_text[0], '\0');
    EXPECT_EQ(SSLFactory::convert_ASN1TIME(nullptr, time_text, sizeof(time_text)),
              EXIT_FAILURE);
    EXPECT_EQ(SSLFactory::convert_ASN1TIME(X509_get0_notBefore(certificate.get()),
                                          nullptr, sizeof(time_text)), EXIT_FAILURE);
    EXPECT_EQ(SSLFactory::convert_ASN1TIME(X509_get0_notBefore(certificate.get()),
                                          time_text, 0), EXIT_FAILURE);

    auto octets = std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)>(
        ASN1_OCTET_STRING_new(), ASN1_OCTET_STRING_free);
    ASSERT_NE(octets, nullptr);
    const unsigned char bytes[] = {0x00, 0x7f, 0xff};
    ASSERT_EQ(ASN1_OCTET_STRING_set(octets.get(), bytes, sizeof(bytes)), 1);
    EXPECT_EQ(SSLFactory::print_ASN1_OCTET_STRING(octets.get()), "007FFF");

    SpoofOptions options;
    options.self_signed = true;
    options.sans = {"DNS:extra.example", "IP:192.0.2.8"};
    const std::string store_key = SSLFactory::make_store_key(certificate.get(), options);
    EXPECT_NE(store_key.find("Smithproxy Server Certificate"), std::string::npos);
    EXPECT_NE(store_key.find("+self_signed"), std::string::npos);
    EXPECT_NE(store_key.find("+san:DNS:extra.example"), std::string::npos);

    auto& factory = SSLFactory::factory();
    EXPECT_FALSE(factory.validate_spoof_requirements(nullptr, nullptr, nullptr, nullptr));
    EXPECT_FALSE(factory.validate_spoof_requirements(certificate.get(), nullptr, nullptr,
                                                     nullptr));
    EXPECT_FALSE(factory.validate_spoof_requirements(
        certificate.get(), X509_get_subject_name(certificate.get()), nullptr, nullptr));
    EXPECT_FALSE(factory.validate_spoof_requirements(
        certificate.get(), X509_get_subject_name(certificate.get()),
        X509_get_issuer_name(certificate.get()), nullptr));
    EXPECT_TRUE(factory.validate_spoof_requirements(
        certificate.get(), X509_get_subject_name(certificate.get()),
        X509_get_issuer_name(certificate.get()), key.get()));

    EXPECT_FALSE(factory.add_custom("test-invalid-certificate", CertificateChainCtx{}));
    EXPECT_FALSE(factory.find_custom("test-certificate-cache-entry").has_value());
    X509_up_ref(certificate.get());
    EVP_PKEY_up_ref(key.get());
    CertificateChainCtx cached(key.get(), certificate.get());
    ASSERT_TRUE(factory.add_custom("test-certificate-cache-entry", cached));
    EXPECT_TRUE(factory.find_custom("test-certificate-cache-entry").has_value());
    EXPECT_FALSE(factory.add_custom("test-certificate-cache-entry", cached));
    EXPECT_TRUE(factory.erase(factory.cache_custom(), "test-certificate-cache-entry"));
    EXPECT_FALSE(factory.find_custom("test-certificate-cache-entry").has_value());
    cached.release();
}

TEST(TLS_Tests, CertificateFactoryLoadsContextsAndGeneratesMitmCertificates) {
    auto source = load_tls_test_certificate();
    ASSERT_NE(source, nullptr);

    auto& factory = SSLFactory::factory();
    const std::string saved_certs_path = factory.certs_path();
    const std::string saved_password = factory.certs_password();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    factory.certs_path() = "etc/certs/default/";
    factory.certs_password() = "smithproxy";
    factory.ca_file() = "etc/certs/default/ca-cert.pem";
    factory.ca_path().clear();
    auto restore_factory = raw::guard([&] {
        factory.destroy();
        factory.certs_path() = saved_certs_path;
        factory.certs_password() = saved_password;
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
    });

    if (!factory.load_from_files()) {
        FAIL() << "test PKI failed to load";
        return;
    }
    EXPECT_TRUE(factory.load_trust_store());

    auto client = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        factory.client_ctx_setup(), SSL_CTX_free);
    auto server = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        factory.server_ctx_setup(), SSL_CTX_free);
    auto dtls_client = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        factory.client_dtls_ctx_setup(), SSL_CTX_free);
    auto dtls_server = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        factory.server_dtls_ctx_setup(), SSL_CTX_free);
    ASSERT_NE(client, nullptr);
    ASSERT_NE(server, nullptr);
    ASSERT_NE(dtls_client, nullptr);
    ASSERT_NE(dtls_server, nullptr);
    ASSERT_NE(factory.trust_store(), nullptr);
    EXPECT_EQ(SSL_CTX_get_cert_store(client.get()), factory.trust_store());
    EXPECT_EQ(SSL_CTX_get_cert_store(server.get()), factory.trust_store());
    EXPECT_EQ(SSL_CTX_get_cert_store(dtls_client.get()), factory.trust_store());
    EXPECT_EQ(SSL_CTX_get_cert_store(dtls_server.get()), factory.trust_store());
    X509_STORE* const central_store = factory.trust_store();
    EXPECT_TRUE(factory.load_trust_store());
    EXPECT_EQ(factory.trust_store(), central_store);
    EXPECT_TRUE(factory.set_verify_locations(client.get()));
    EXPECT_EQ(SSL_CTX_get_cert_store(client.get()), factory.trust_store());

    std::vector<std::string> extra_sans {"DNS:extra.example", "IP:192.0.2.8"};
    auto request = factory.create_csr_from(source.get(), false, &extra_sans);
    ASSERT_TRUE(request.has_value());
    EXPECT_NE(X509_REQ_get_subject_name(*request), nullptr);
    X509_REQ_free(*request);

    auto generated = factory.spoof(source.get(), false, &extra_sans);
    ASSERT_TRUE(generated.has_value());
    ASSERT_NE(generated->chain.cert, nullptr);
    EXPECT_EQ(X509_check_host(generated->chain.cert, "extra.example", 0, 0, nullptr), 1);
    X509_free(generated->chain.cert);
    generated->nullify(); // spoof() lends the factory-owned server key.

    auto self_signed = factory.spoof(source.get(), true, nullptr);
    ASSERT_TRUE(self_signed.has_value());
    ASSERT_NE(self_signed->chain.cert, nullptr);
    EXPECT_EQ(X509_NAME_cmp(X509_get_subject_name(self_signed->chain.cert),
                            X509_get_issuer_name(self_signed->chain.cert)), 0);
    X509_free(self_signed->chain.cert);
    self_signed->nullify();

    std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> cached_session(
        SSL_SESSION_new(), SSL_SESSION_free);
    ASSERT_NE(cached_session, nullptr);
    factory.session_cache().set(
        "trust-generation-session",
        new session_holder(cached_session.release()));

    std::unique_ptr<X509_CRL, decltype(&X509_CRL_free)> cached_crl(
        X509_CRL_new(), X509_CRL_free);
    ASSERT_NE(cached_crl, nullptr);
    factory.crl_cache().set(
        "trust-generation-crl",
        SSLFactory::make_expiring_crl(cached_crl.release()));

    EXPECT_TRUE(factory.reset_caches());
    EXPECT_EQ(factory.session_cache().get("trust-generation-session"), nullptr);
    EXPECT_EQ(factory.crl_cache().get("trust-generation-crl"), nullptr);

    client.reset();
    server.reset();
    dtls_client.reset();
    dtls_server.reset();
}

TEST(TLS_Tests, TrustStoreTeardownInvalidatesCachedSessions) {
    auto& factory = SSLFactory::factory();
    std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> session(
        SSL_SESSION_new(), SSL_SESSION_free);
    ASSERT_NE(session, nullptr);
    factory.session_cache().set(
        "old-trust-generation", new session_holder(session.release()));
    ASSERT_NE(factory.session_cache().get("old-trust-generation"), nullptr);

    factory.destroy();
    EXPECT_EQ(factory.session_cache().get("old-trust-generation"), nullptr);
}

TEST(TLS_Tests, InvalidCrlCacheTtlUsesBoundedFallback) {
    const int saved_ttl = SSLFactory::options::crl_status_ttl;
    auto restore_ttl = raw::guard([&] {
        SSLFactory::options::crl_status_ttl = saved_ttl;
    });

    SSLFactory::options::crl_status_ttl = -1;
    std::unique_ptr<SSLFactory::expiring_crl> entry(
        SSLFactory::make_expiring_crl(nullptr));
    ASSERT_NE(entry, nullptr);

    const time_t now = ::time(nullptr);
    EXPECT_GT(entry->expired_at(), now);
    EXPECT_LE(entry->expired_at(), now + 86400);
}

TEST(TLS_Tests, CrlCacheExpiresNoLaterThanNextUpdate) {
    const int saved_ttl = SSLFactory::options::crl_status_ttl;
    auto restore_ttl = raw::guard([&] {
        SSLFactory::options::crl_status_ttl = saved_ttl;
    });
    SSLFactory::options::crl_status_ttl = 86400;

    X509_CRL* crl = X509_CRL_new();
    ASSERT_NE(crl, nullptr);
    ASN1_TIME* next_update = ASN1_TIME_adj(nullptr, ::time(nullptr), 0, 45);
    ASSERT_NE(next_update, nullptr);
    ASSERT_EQ(X509_CRL_set1_nextUpdate(crl, next_update), 1);
    ASN1_TIME_free(next_update);

    const time_t before = ::time(nullptr);
    std::unique_ptr<SSLFactory::expiring_crl> entry(
        SSLFactory::make_expiring_crl(crl));
    const time_t after = ::time(nullptr);
    ASSERT_NE(entry, nullptr);
    EXPECT_GT(entry->expired_at(), before);
    EXPECT_LE(entry->expired_at(), after + 45);

    X509_CRL* expired_crl = X509_CRL_new();
    ASSERT_NE(expired_crl, nullptr);
    next_update = ASN1_TIME_adj(nullptr, ::time(nullptr), 0, -1);
    ASSERT_NE(next_update, nullptr);
    ASSERT_EQ(X509_CRL_set1_nextUpdate(expired_crl, next_update), 1);
    ASN1_TIME_free(next_update);
    std::unique_ptr<SSLFactory::expiring_crl> expired_entry(
        SSLFactory::make_expiring_crl(expired_crl));
    ASSERT_NE(expired_entry, nullptr);
    EXPECT_TRUE(expired_entry->expired());
}

TEST(TLS_Tests, CertificateFactoryRejectsMissingPkiAndTrustLocations) {
    auto& factory = SSLFactory::factory();
    const std::string saved_certs_path = factory.certs_path();
    const std::string saved_password = factory.certs_password();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    auto restore_factory = raw::guard([&] {
        factory.destroy();
        factory.certs_path() = saved_certs_path;
        factory.certs_password() = saved_password;
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
    });

    factory.destroy();
    factory.certs_path() = "/definitely/missing/smithproxy-pki/";
    factory.certs_password() = "wrong";
    EXPECT_FALSE(factory.load_from_files());

    factory.ca_file() = "/definitely/missing/ca-bundle.pem";
    factory.ca_path().clear();
    EXPECT_FALSE(factory.load_trust_store());
    auto context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(context, nullptr);
    EXPECT_FALSE(factory.set_verify_locations(context.get()));

    factory.ca_file().clear();
    factory.ca_path().clear();
    EXPECT_FALSE(factory.load_trust_store());
    EXPECT_FALSE(factory.set_verify_locations(context.get()));
}

TEST(TLS_Tests, CertificateFactoryLoadsCustomFullchainAndSplitChainLayouts) {
    namespace fs = std::filesystem;
    Log::init();
    Log::get()->level(WAR);
    auto& factory = SSLFactory::factory();
    const std::string saved_certs_path = factory.certs_path();
    const std::string saved_password = factory.certs_password();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    const fs::path temp = fs::temp_directory_path()
        / ("smithproxy-custom-pki-" + std::to_string(::getpid()));
    fs::remove_all(temp);
    auto restore_factory = raw::guard([&] {
        factory.destroy();
        factory.certs_path() = saved_certs_path;
        factory.certs_password() = saved_password;
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
        fs::remove_all(temp);
    });

    factory.certs_path() = "etc/certs/default/";
    factory.certs_password() = "smithproxy";
    factory.ca_file() = "etc/certs/default/ca-cert.pem";
    factory.ca_path().clear();
    ASSERT_TRUE(factory.load_from_files());

    const fs::path fullchain = temp / "sni" / "fullchain.example";
    const fs::path split = temp / "ip" / "192.0.2.10";
    fs::create_directories(fullchain);
    fs::create_directories(split);
    fs::copy_file("etc/certs/default/srv-cert.pem", fullchain / "fullchain.pem");
    fs::copy_file("etc/certs/default/srv-key.pem", fullchain / "key.pem");
    fs::copy_file("etc/certs/default/srv-cert.pem", split / "cert.pem");
    fs::copy_file("etc/certs/default/srv-key.pem", split / "key.pem");
    fs::copy_file("etc/certs/default/ca-cert.pem", split / "issuer.pem");

    factory.certs_path() = temp.string() + "/";
    EXPECT_TRUE(factory.load_custom_certificates());
    EXPECT_TRUE(factory.find_custom("sni:fullchain.example").has_value());
    EXPECT_TRUE(factory.find_custom("ip:192.0.2.10").has_value());
    EXPECT_TRUE(factory.erase(factory.cache_custom(), "sni:fullchain.example"));
    EXPECT_TRUE(factory.erase(factory.cache_custom(), "ip:192.0.2.10"));
}

TEST(TLS_Tests, OutboundSniRewriteExactMatch) {
    baseHostCX target(new TCPCom(), "192.0.2.1", "443");
    target.configure_sni_rewrite("client.example", "origin.internal");

    EXPECT_EQ(target.outbound_sni("client.example"), "origin.internal");
    EXPECT_EQ(target.outbound_sni("other.example"), "other.example");
}

TEST(TLS_Tests, OutboundSniRewriteRequiresBothValues) {
    baseHostCX target(new TCPCom(), "192.0.2.1", "443");
    target.configure_sni_rewrite("client.example", "");
    EXPECT_EQ(target.outbound_sni("client.example"), "client.example");

    target.configure_sni_rewrite("", "origin.internal");
    EXPECT_EQ(target.outbound_sni("client.example"), "client.example");
}


unsigned char tls_sni_smithproxy[] = {
        0x16, 0x03, 0x01, 0x01, 0x62, 0x01, 0x00, 0x01,
        0x5e, 0x03, 0x03, 0x34, 0x4f, 0x0a, 0x93, 0x4b,
        0xe7, 0x65, 0x90, 0x0f, 0x9d, 0x14, 0xd5, 0x0a,
        0xc4, 0xbf, 0x28, 0x56, 0x68, 0x33, 0xb8, 0xa5,
        0x91, 0xb1, 0x4d, 0x4c, 0xdf, 0xb9, 0x9d, 0x6b,
        0x0a, 0x34, 0x84, 0x20, 0x3d, 0xbb, 0x6a, 0x05,
        0x4c, 0x2a, 0x06, 0x48, 0x1c, 0x39, 0x0b, 0x50,
        0x13, 0x3f, 0x6f, 0x42, 0x85, 0x1b, 0xeb, 0x79,
        0x52, 0x0d, 0x83, 0x93, 0xa6, 0xd7, 0xa1, 0x57,
        0x7c, 0x0d, 0x54, 0x3d, 0x00, 0x66, 0x13, 0x02,
        0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30,
        0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa,
        0xc0, 0xaf, 0xc0, 0xad, 0xc0, 0xa3, 0xc0, 0x9f,
        0xc0, 0x5d, 0xc0, 0x61, 0xc0, 0x53, 0xc0, 0x24,
        0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x0a, 0xc0, 0x14,
        0x00, 0x39, 0x00, 0x9d, 0xc0, 0xa1, 0xc0, 0x9d,
        0xc0, 0x51, 0x00, 0x3d, 0x00, 0x35, 0xc0, 0x2b,
        0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0xae, 0xc0, 0xac,
        0xc0, 0xa2, 0xc0, 0x9e, 0xc0, 0x5c, 0xc0, 0x60,
        0xc0, 0x52, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9c,
        0xc0, 0xa0, 0xc0, 0x9c, 0xc0, 0x50, 0x00, 0x3c,
        0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0xaf,
        0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00,
        0x0e, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x70, 0x72,
        0x6f, 0x78, 0x79, 0x2e, 0x6f, 0x72, 0x67, 0x00,
        0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00,
        0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00,
        0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x00,
        0x23, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00,
        0x00, 0x12, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
        0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03,
        0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
        0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04,
        0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
        0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02,
        0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b,
        0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00,
        0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00,
        0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x92,
        0x14, 0xa1, 0x86, 0xf9, 0x13, 0x4a, 0x8d, 0x3f,
        0x73, 0x26, 0xc2, 0x57, 0x15, 0xa6, 0x97, 0xb8,
        0xeb, 0x49, 0x51, 0xb4, 0x9c, 0x61, 0x60, 0xc6,
        0xa9, 0xd3, 0xa6, 0xc2, 0x08, 0x24, 0x33
};


unsigned char tls_sni_smithproxy_alpn[] = {
        0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01,
        0xfc, 0x03, 0x03, 0xef, 0x38, 0x34, 0x82, 0xd4,
        0x72, 0x82, 0x85, 0xf4, 0xdd, 0x9f, 0xef, 0xcb,
        0xff, 0x58, 0x24, 0xe8, 0xd3, 0xe8, 0x34, 0x76,
        0xae, 0xdd, 0xb4, 0x65, 0xa1, 0xdf, 0x50, 0x76,
        0x55, 0xfd, 0x61, 0x20, 0x03, 0xcb, 0x43, 0x47,
        0x19, 0x94, 0x2d, 0x5c, 0x59, 0xd6, 0xbd, 0x7e,
        0x9f, 0x3b, 0xd6, 0x96, 0x1a, 0x16, 0x22, 0x0b,
        0x53, 0x6a, 0xbf, 0x6c, 0x36, 0x90, 0x22, 0x87,
        0xb1, 0x68, 0x52, 0x32, 0x00, 0x3e, 0x13, 0x02,
        0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30,
        0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa,
        0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e, 0xc0, 0x24,
        0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27,
        0x00, 0x67, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39,
        0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d,
        0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35,
        0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x01, 0x75,
        0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00,
        0x0e, 0x73, 0x6d, 0x69, 0x74, 0x68, 0x70, 0x72,
        0x6f, 0x78, 0x79, 0x2e, 0x6f, 0x72, 0x67, 0x00,
        0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00,
        0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00,
        0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x33,
        0x74, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00,
        0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74,
        0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x16, 0x00,
        0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x31, 0x00,
        0x00, 0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04,
        0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08,
        0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08,
        0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05,
        0x01, 0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03,
        0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00,
        0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03,
        0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33,
        0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
        0xb0, 0x57, 0x60, 0xb9, 0x12, 0xd1, 0xdd, 0x1f,
        0xc8, 0xd1, 0xb2, 0x15, 0xd0, 0xe2, 0xa1, 0x55,
        0x0a, 0x6e, 0x97, 0x7f, 0xc8, 0x6a, 0x3b, 0x78,
        0xee, 0xda, 0xae, 0xae, 0xbe, 0xd9, 0x15, 0x4c,
        0x00, 0x15, 0x00, 0xb9, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00
};


// Correct ClientHello sent by M$ teams, interesting/rare because it doesn't have any extensions.
//  Original peeks 50bytes, excess data are memory garbage to make sure
// they are not valid (and they are not, since message size is 45B, and index 52 where extensions length is placed
// says the ext length is 1280).
unsigned char tls_teams_50[] = {
        0x16, 0x03, 0x01, 0x00,   0x2d, 0x01, 0x00, 0x00,   0x29, 0x03, 0x01, 0x60,   0xeb, 0xe7, 0xf5, 0xff,
        0x64, 0x54, 0xc0, 0xe3,   0x3a, 0x9a, 0x20, 0x3a,   0xd4, 0xb3, 0xa7, 0xa2,   0x22, 0x45, 0xef, 0x92,
        0x3e, 0x7e, 0x18, 0x3b,   0xf5, 0xb2, 0x05, 0xd4,   0xc1, 0xb3, 0xe3, 0x00,   0x00, 0x02, 0x00, 0x18,
        0x01, 0x00, 0x05, 0x00,   0x01, 0x00, 0x00, 0x01,   0xa5, 0x00, 0x26, 0x11,   0x74, 0x65, 0x61, 0x6d,
        0x73, 0x2d, 0x65, 0x76,   0x65, 0x6e, 0x74, 0x73,   0x2d, 0x64, 0x61, 0x74,   0x61, 0x0e, 0x74, 0x72,
        0x61, 0x66, 0x66, 0x69,   0x63, 0x6d, 0x61, 0x6e,   0x61, 0x67, 0x65, 0x72,   0x03, 0x6e, 0x65, 0x74,
        0x00, 0xc0, 0x3b, 0x00,   0x05, 0x00, 0x01, 0x00,   0x00, 0x00, 0x0a, 0x00,   0x20, 0x14, 0x73, 0x6b,
        0x79, 0x70, 0x65, 0x64,   0x61, 0x74, 0x61, 0x70,   0x72, 0x64, 0x63, 0x6f,   0x6c, 0x63, 0x75, 0x73,
        0x30, 0x31, 0x08, 0x63,   0x6c, 0x6f, 0x75, 0x64,   0x61, 0x70, 0x70, 0xc0,   0x5c, 0xc0, 0x6d, 0x00,
        0x01, 0x00, 0x01, 0x00,   0x00, 0x00, 0x05, 0x00,   0x04, 0x34, 0x72, 0x80,   0x4b, 0xb5, 0x25, 0x62,
        0xd5, 0xdf, 0x8f, 0xae,   0x44, 0x2d, 0x5d, 0x87,   0x91, 0x61, 0xfb, 0x41,   0x16, 0x2d, 0xbe, 0x0a,
        0xb0, 0x03, 0x40, 0x8c,   0xf2, 0xb5, 0x28, 0x58,   0x94, 0x18, 0xb5, 0x25,   0x64, 0xfa, 0xac, 0xbf,
        0x85, 0x90, 0xa8, 0xea,   0x93, 0xd7, 0x57, 0xff,   0xe8, 0x09, 0xba, 0x51,   0xd8, 0x5b, 0x14, 0x2f,
        0xac, 0xa0, 0x2f, 0xe4,   0x26, 0xd4, 0x6c, 0xb9,   0xb8, 0x87, 0x61, 0xb3,   0xde, 0xcb, 0x6c, 0x62,
        0x6f, 0xa7, 0xee, 0xec,   0x8e, 0x64, 0xaa, 0x87,   0x35, 0x6f, 0xcb, 0x86,   0x4c, 0x12, 0x72, 0xdf
};


static auto const LEVEL = loglevel(iDEB);
static void init_log() {
    Log::init();
    Log::get()->level(LEVEL);
    Log::get()->dup2_cout(true);
}

struct SSLCom_Buddy : public SSLCom {
    void test_peer_hello_buffer(buffer const& b) { sslcom_peer_hello_buffer.assign( (void*)b.data(), b.size(), b.size(), false); }
    const unsigned char* test_peer_hello_data() const { return sslcom_peer_hello_buffer.data(); }
    int test_parse_sni() { return parse_peer_hello(); }
    unsigned short test_parse_extension(buffer& b) { return parse_peer_hello_extensions(b, 0); }
    int test_normalize_records() { return static_cast<int>(normalize_peer_hello_records()); }
    int test_handshake_client() { return handshake_client(); }
    bool test_check_cert(const char* host = nullptr) { return check_cert(host); }
    void test_take_ssl(SSL* ssl) { sslcom_ssl = ssl; }
    SSL* test_ssl() const { return sslcom_ssl; }
    void test_alpn(std::string value) { sslcom_alpn_ = std::move(value); }
    void test_server(bool value) { is_server(value); }
    std::string test_flags() { return flags_str(); }
    void test_peer_hello_received(bool value) { sslcom_peer_hello_received(value); }
    void test_sni(std::string value) { sslcom_sni() = std::move(value); }
    bool test_handshake_peer_client() { return handshake_peer_client(); }
    void test_init_ssl_callbacks() { init_ssl_callbacks(); }
    void test_context(SSL_CTX* context) { sslcom_ctx = context; }
    void test_init_server() { init_server(); }
    bool test_waiting_peer_hello() { return waiting_peer_hello(); }
    int test_handshake_result() { return static_cast<int>(handshake()); }
    void test_expire_handshake_timer() {
        gettimeofday(&timer_start, nullptr);
        timer_start.tv_sec -= 60;
    }
    void test_expire_tls_handshake_timer() {
        gettimeofday(&timer_handshake_start, nullptr);
        timer_handshake_start.tv_sec -= 60;
        handshake_timer_started = true;
    }
    void test_peer_chain(X509* certificate, X509* issuer) {
        ASSERT_NE(certificate, nullptr);
        ASSERT_NE(issuer, nullptr);
        ASSERT_EQ(X509_up_ref(certificate), 1);
        ASSERT_EQ(X509_up_ref(issuer), 1);
        sslcom_target_cert = certificate;
        sslcom_target_issuer = issuer;
    }
    void test_peer_chain_three(X509* certificate, X509* issuer, X509* root) {
        test_peer_chain(certificate, issuer);
        ASSERT_NE(root, nullptr);
        ASSERT_EQ(X509_up_ref(root), 1);
        sslcom_target_issuer_issuer = root;
    }
};

struct SSLMitmCom_Buddy : public SSLMitmCom {
    bool capture_spoof_options = false;
    std::optional<SpoofOptions> captured_spoof_options;
    X509* test_preferred_cert() const { return sslcom_pref_cert; }
    EVP_PKEY* test_preferred_key() const { return sslcom_pref_key; }
    SSL* test_ssl() const { return sslcom_ssl; }
    void test_context(SSL_CTX* context) { sslcom_ctx = context; }
    void test_init_server() { init_server(); }
    void test_take_ssl(SSL* ssl) { sslcom_ssl = ssl; }
    void test_sni(std::string value) { sslcom_sni() = std::move(value); }
    void test_peer_sni_shortcut(bool value) { sslcom_peer_sni_shortcut = value; }
    void test_resume_delayed_accept() { resume_delayed_accept(this); }
    bool spoof_cert(X509* certificate, SpoofOptions& options) override {
        if(capture_spoof_options) {
            captured_spoof_options = options;
            return certificate != nullptr;
        }
        return SSLMitmCom::spoof_cert(certificate, options);
    }
};

struct MemoryTlsPair {
    std::unique_ptr<SSL, decltype(&SSL_free)> client {nullptr, SSL_free};
    std::unique_ptr<SSL, decltype(&SSL_free)> server {nullptr, SSL_free};
};

TEST(TLS_Tests, WildcardSniBypassRequiresAnActualSubdomain) {
    auto is_bypassed = [](std::string sni) {
        SSLCom_Buddy client;
        SSLCom_Buddy peer;
        client.peer(&peer);
        peer.peer(&client);
        client.auto_upgrade(false);
        client.test_peer_hello_received(true);
        client.sni_filter_to_bypass() =
            std::make_shared<std::vector<std::string>>(
                std::initializer_list<std::string>{"*.example.test"});
        client.test_sni(std::move(sni));

        bool const handshake_continues = client.test_handshake_peer_client();
        EXPECT_EQ(client.opt.bypass, peer.opt.bypass);
        EXPECT_EQ(handshake_continues, !client.opt.bypass);
        return client.opt.bypass;
    };

    EXPECT_FALSE(is_bypassed(""));
    EXPECT_FALSE(is_bypassed("example.test"));
    EXPECT_FALSE(is_bypassed("notexample.test"));
    EXPECT_TRUE(is_bypassed("api.example.test"));
    EXPECT_TRUE(is_bypassed("deep.api.example.test"));
}

TEST(TLS_Tests, PartialClientHelloTimesOutAndFailsBothTlsSides) {
    int sockets[2] {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sockets), 0);

    SSLCom_Buddy outbound;
    SSLCom_Buddy inbound;
    outbound.peer(&inbound);
    inbound.peer(&outbound);
    inbound.socket(sockets[0]);
    outbound.test_expire_handshake_timer();
    outbound.opt.client_hello_timeout = 1;

    // A TLS record header promising a longer ClientHello body. The peer must
    // not be allowed to keep the pre-handshake connection alive indefinitely.
    const unsigned char partial[] {0x16, 0x03, 0x03, 0x00, 0x40, 0x01};
    ASSERT_EQ(::send(sockets[1], partial, sizeof(partial), MSG_NOSIGNAL),
              static_cast<ssize_t>(sizeof(partial)));

    EXPECT_FALSE(outbound.test_waiting_peer_hello());
    EXPECT_TRUE(outbound.error());
    EXPECT_TRUE(inbound.error());

    outbound.socket(0);
    inbound.socket(0);
    ::close(sockets[0]);
    ::close(sockets[1]);
}

TEST(TLS_Tests, ExpiredTlsHandshakeFailsBothSidesBeforeAnotherRetry) {
    init_log();
    SSLCom_Buddy connection;
    SSLCom_Buddy peer;
    connection.peer(&peer);
    peer.peer(&connection);
    connection.opt.handshake_timeout = 1;
    connection.test_expire_tls_handshake_timer();

    EXPECT_EQ(connection.test_handshake_result(),
              static_cast<int>(ret_handshake::FATAL));
    EXPECT_TRUE(connection.error());
    EXPECT_TRUE(peer.error());
}

MemoryTlsPair make_memory_tls_pair(SSL_CTX* client_context, SSL_CTX* server_context,
                                   SSLCom* client_owner = nullptr) {
    MemoryTlsPair pair;
    pair.client.reset(SSL_new(client_context));
    pair.server.reset(SSL_new(server_context));
    if(not pair.client or not pair.server) return pair;
    if(client_owner &&
       SSL_set_ex_data(pair.client.get(), SSLCom::extdata_index(), client_owner) != 1) {
        return {};
    }

    BIO* client_bio = nullptr;
    BIO* server_bio = nullptr;
    if(BIO_new_bio_pair(&client_bio, 0, &server_bio, 0) != 1) return {};
    SSL_set_bio(pair.client.get(), client_bio, client_bio);
    SSL_set_bio(pair.server.get(), server_bio, server_bio);
    SSL_set_connect_state(pair.client.get());
    SSL_set_accept_state(pair.server.get());

    bool client_done = false;
    bool server_done = false;
    for(int attempt = 0; attempt < 100 and not (client_done and server_done); ++attempt) {
        if(not client_done) {
            const int result = SSL_do_handshake(pair.client.get());
            client_done = result == 1;
            if(not client_done) {
                const int error = SSL_get_error(pair.client.get(), result);
                if(error != SSL_ERROR_WANT_READ and error != SSL_ERROR_WANT_WRITE) return {};
            }
        }
        if(not server_done) {
            const int result = SSL_do_handshake(pair.server.get());
            server_done = result == 1;
            if(not server_done) {
                const int error = SSL_get_error(pair.server.get(), result);
                if(error != SSL_ERROR_WANT_READ and error != SSL_ERROR_WANT_WRITE) return {};
            }
        }
    }
    if(not client_done or not server_done) return {};
    return pair;
}

TEST(TLS_Tests, ClientCertificateActionsCompleteTls12AndTls13RequestsSafely) {
    init_log();
    auto certificate = load_tls_test_certificate();
    auto key = load_tls_test_key();
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(key, nullptr);

    for(const int version : {TLS1_2_VERSION, TLS1_3_VERSION}) {
        for(const int action : {0, 1, 2, 3}) {
            auto client_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
                SSL_CTX_new(TLS_method()), SSL_CTX_free);
            auto server_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
                SSL_CTX_new(TLS_method()), SSL_CTX_free);
            ASSERT_NE(client_context, nullptr);
            ASSERT_NE(server_context, nullptr);
            ASSERT_EQ(SSL_CTX_set_min_proto_version(client_context.get(), version), 1);
            ASSERT_EQ(SSL_CTX_set_max_proto_version(client_context.get(), version), 1);
            ASSERT_EQ(SSL_CTX_set_min_proto_version(server_context.get(), version), 1);
            ASSERT_EQ(SSL_CTX_set_max_proto_version(server_context.get(), version), 1);
            SSL_CTX_set_client_cert_cb(
                client_context.get(), SSLCom::ssl_client_cert_callback);
            SSL_CTX_set_verify(server_context.get(), SSL_VERIFY_PEER,
                               [](int, X509_STORE_CTX*) { return 1; });
            ASSERT_EQ(SSL_CTX_use_certificate(
                          server_context.get(), certificate.get()), 1);
            ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), key.get()), 1);

            SSLCom_Buddy connection;
            connection.opt.cert.client_cert_action = action;
            connection.opt.cert.failed_check_replacement = action == 0;
            auto tls = make_memory_tls_pair(
                client_context.get(), server_context.get(), &connection);
            EXPECT_NE(tls.client, nullptr)
                << "TLS version " << version << ", action " << action;
            EXPECT_NE(tls.server, nullptr)
                << "TLS version " << version << ", action " << action;
            EXPECT_TRUE(connection.verify_bitcheck(
                SSLCom::verify_status_t::VRF_CLIENT_CERT_RQ));
            if(tls.server) {
                EXPECT_EQ(SSL_get_peer_certificate(tls.server.get()), nullptr);
            }
        }
    }
}

TEST(TLS_Tests, CertificateTransparencyStatusNamesCoverEveryOpenSslValue) {
    using socle::com::ssl::SCT_validation_status_str;

    EXPECT_STREQ(SCT_validation_status_str(SCT_VALIDATION_STATUS_NOT_SET),
                 "SCT_VALIDATION_STATUS_NOT_SET");
    EXPECT_STREQ(SCT_validation_status_str(SCT_VALIDATION_STATUS_UNKNOWN_LOG),
                 "SCT_VALIDATION_STATUS_UNKNOWN_LOG");
    EXPECT_STREQ(SCT_validation_status_str(SCT_VALIDATION_STATUS_VALID),
                 "SCT_VALIDATION_STATUS_VALID");
    EXPECT_STREQ(SCT_validation_status_str(SCT_VALIDATION_STATUS_INVALID),
                 "SCT_VALIDATION_STATUS_INVALID");
    EXPECT_STREQ(SCT_validation_status_str(SCT_VALIDATION_STATUS_UNVERIFIED),
                 "SCT_VALIDATION_STATUS_UNVERIFIED");
    EXPECT_STREQ(SCT_validation_status_str(SCT_VALIDATION_STATUS_UNKNOWN_VERSION),
                 "SCT_VALIDATION_STATUS_UNKNOWN_VERSION");
    EXPECT_STREQ(SCT_validation_status_str(
                     static_cast<sct_validation_status_t>(-1)),
                 "???");
}

TEST(TLS_Tests, VerifyCallbackRejectsIncompleteOpenSslState) {
    EXPECT_EQ(SSLCom::ssl_client_vrfy_callback(1, nullptr), 0);

    auto* store = X509_STORE_CTX_new();
    ASSERT_NE(store, nullptr);
    EXPECT_EQ(SSLCom::ssl_client_vrfy_callback(1, store), 0);
    X509_STORE_CTX_free(store);
}

TEST(TLS_Tests, ClientHandshakeRejectsMissingSslObject) {
    SSLCom_Buddy client;
    EXPECT_EQ(client.test_handshake_client(), -1);
    EXPECT_TRUE(client.error());
}

TEST(TLS_Tests, CertificateCheckRejectsMissingSslState) {
    SSLCom_Buddy client;
    EXPECT_FALSE(client.test_check_cert());

    SSLMitmCom mitm;
    EXPECT_FALSE(mitm.check_cert(nullptr));

    auto context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(context, nullptr);
    SSLCom_Buddy no_peer_certificate;
    no_peer_certificate.test_take_ssl(SSL_new(context.get()));
    ASSERT_NE(no_peer_certificate.test_ssl(), nullptr);
    EXPECT_FALSE(no_peer_certificate.test_check_cert("missing-peer.example"));
}

TEST(TLS_Tests, MitmCertificateSelectionRequiresAnExplicitAvailableSource) {
    auto certificate = load_tls_test_certificate();
    auto key = load_tls_test_key();
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(key, nullptr);

    auto& factory = SSLFactory::factory();
    constexpr auto cache_key = "sni:coverage-custom.example";
    factory.erase(factory.cache_custom(), cache_key);
    CertificateChainCtx cached(key.get(), certificate.get());
    ASSERT_TRUE(factory.add_custom(cache_key, cached));

    SSLMitmCom_Buddy connection;
    connection.factory(&factory);
    SpoofOptions options;

    EXPECT_FALSE(connection.use_cert_sni(options));
    EXPECT_FALSE(connection.use_cert_ip(options));

    options.sni = "coverage-custom.example";
    EXPECT_TRUE(connection.use_cert_sni(options));
    EXPECT_EQ(connection.test_preferred_cert(), certificate.get());
    EXPECT_EQ(connection.test_preferred_key(), key.get());

    EXPECT_FALSE(connection.use_cert_null());
    EXPECT_EQ(connection.test_preferred_cert(), nullptr);
    EXPECT_EQ(connection.test_preferred_key(), nullptr);

    connection.opt.cert.mitm_cert_sni_search = true;
    connection.opt.cert.mitm_cert_searched_only = true;
    options.sni = "missing-custom.example";
    EXPECT_FALSE(connection.spoof_cert(certificate.get(), options));
    EXPECT_TRUE(connection.error());

    EXPECT_TRUE(factory.erase(factory.cache_custom(), cache_key));

    SSLMitmCom_Buddy missing_origin;
    missing_origin.factory(&factory);
    SpoofOptions no_explicit_source;
    EXPECT_FALSE(missing_origin.spoof_cert(nullptr, no_explicit_source));
    EXPECT_TRUE(missing_origin.error());
    EXPECT_EQ(missing_origin.test_preferred_cert(), nullptr);
    EXPECT_EQ(missing_origin.test_preferred_key(), nullptr);
}

TEST(TLS_Tests, MitmCertificateGenerationIsCachedAndReusable) {
    auto source = load_tls_test_certificate();
    ASSERT_NE(source, nullptr);

    auto& factory = SSLFactory::factory();
    const std::string saved_certs_path = factory.certs_path();
    const std::string saved_password = factory.certs_password();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    factory.destroy();
    factory.certs_path() = "etc/certs/default/";
    factory.certs_password() = "smithproxy";
    factory.ca_file() = "etc/certs/default/ca-cert.pem";
    factory.ca_path().clear();
    auto restore_factory = raw::guard([&] {
        factory.destroy();
        factory.certs_path() = saved_certs_path;
        factory.certs_password() = saved_password;
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
    });
    ASSERT_TRUE(factory.load_from_files());
    auto server_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        factory.server_ctx_setup(), SSL_CTX_free);
    ASSERT_NE(server_context, nullptr);

    SpoofOptions options;
    options.sni = "generated-cache.example";
    options.sans = {"DNS:generated-cache.example", "IP:192.0.2.44"};
    const auto store_key = SSLFactory::make_store_key(source.get(), options);
    factory.erase(factory.cache_mitm(), store_key);

    SSLMitmCom_Buddy cold;
    cold.factory(&factory);
    cold.l4_proto(SOCK_STREAM);
    cold.test_context(server_context.get());
    ASSERT_TRUE(cold.use_cert_mitm(source.get(), options));
    ASSERT_NE(cold.test_preferred_cert(), nullptr);
    ASSERT_NE(cold.test_preferred_key(), nullptr);
    EXPECT_EQ(X509_check_host(cold.test_preferred_cert(),
                              "generated-cache.example", 0, 0, nullptr), 1);
    EXPECT_EQ(X509_check_ip_asc(cold.test_preferred_cert(), "192.0.2.44", 0), 1);
    auto* generated = cold.test_preferred_cert();
    cold.test_init_server();
    EXPECT_NE(cold.test_ssl(), nullptr);

    SSLMitmCom_Buddy cached;
    cached.factory(&factory);
    cached.l4_proto(SOCK_STREAM);
    cached.test_context(server_context.get());
    ASSERT_TRUE(cached.use_cert_mitm(source.get(), options));
    EXPECT_EQ(cached.test_preferred_cert(), generated);
    cached.test_init_server();
    EXPECT_NE(cached.test_ssl(), nullptr);

    EXPECT_TRUE(factory.erase(factory.cache_mitm(), store_key));
}

TEST(TLS_Tests, MitmCertificateCacheSeparatesRotatedOriginCertificates) {
    auto first_key = make_rsa_key();
    auto second_key = make_rsa_key();
    ASSERT_NE(first_key, nullptr);
    ASSERT_NE(second_key, nullptr);

    auto first = make_certificate(first_key.get(), 5101, "rotated.example");
    auto second = make_certificate(second_key.get(), 5102, "rotated.example");
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);

    SpoofOptions options;
    EXPECT_NE(SSLFactory::make_store_key(first.get(), options),
              SSLFactory::make_store_key(second.get(), options));
}

TEST(TLS_Tests, MitmHostnameValidationUsesTheNegotiatedPeerCertificate) {
    auto certificate = load_tls_test_certificate();
    auto key = load_tls_test_key();
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(key, nullptr);

    auto client_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    auto server_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(client_context, nullptr);
    ASSERT_NE(server_context, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate.get()), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), key.get()), 1);
    ASSERT_EQ(SSL_CTX_check_private_key(server_context.get()), 1);

    auto check_name = [&](std::string const& sni) {
        auto tls = make_memory_tls_pair(client_context.get(), server_context.get());
        EXPECT_NE(tls.client, nullptr);
        EXPECT_NE(tls.server, nullptr);

        SSLMitmCom_Buddy upstream;
        SSLMitmCom_Buddy downstream;
        upstream.peer(&downstream);
        downstream.peer(&upstream);
        upstream.test_take_ssl(tls.client.release());
        upstream.verify_reset(SSLCom::verify_status_t::VRF_OK);
        upstream.test_sni(sni);
        upstream.test_peer_sni_shortcut(true);
        EXPECT_TRUE(upstream.check_cert(nullptr));
        return upstream.verify_bitcheck(SSLCom::verify_status_t::VRF_HOSTNAME_FAILED);
    };

    EXPECT_FALSE(check_name("Smithproxy-Server-Certificate"));
    EXPECT_TRUE(check_name("wrong-hostname.example"));
}

TEST(TLS_Tests, MitmHostnameValidationDoesNotLetCommonNameOverrideDnsSan) {
    auto key = make_rsa_key();
    auto certificate = make_certificate(
        key.get(), 4001, "requested.example");
    ASSERT_NE(key, nullptr);
    ASSERT_NE(certificate, nullptr);
    ASSERT_TRUE(add_certificate_extension(
        certificate.get(), NID_subject_alt_name, "DNS:other.example"));
    ASSERT_GT(X509_sign(certificate.get(), key.get(), EVP_sha256()), 0);
    ASSERT_EQ(X509_check_host(certificate.get(), "requested.example", 0, 0, nullptr), 0);
    ASSERT_EQ(X509_check_host(certificate.get(), "requested.example", 0,
                              X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT, nullptr), 1);

    auto client_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    auto server_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(client_context, nullptr);
    ASSERT_NE(server_context, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate.get()), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), key.get()), 1);

    auto tls = make_memory_tls_pair(client_context.get(), server_context.get());
    ASSERT_NE(tls.client, nullptr);
    ASSERT_NE(tls.server, nullptr);

    SSLMitmCom_Buddy upstream;
    SSLMitmCom_Buddy downstream;
    upstream.peer(&downstream);
    downstream.peer(&upstream);
    upstream.test_take_ssl(tls.client.release());
    upstream.verify_reset(SSLCom::verify_status_t::VRF_OK);
    upstream.test_sni("requested.example");
    upstream.test_peer_sni_shortcut(true);
    EXPECT_TRUE(upstream.check_cert(nullptr));
    EXPECT_TRUE(upstream.verify_bitcheck(SSLCom::verify_status_t::VRF_HOSTNAME_FAILED));
}

TEST(TLS_Tests, NumericSniRequiresAnIpSubjectAltName) {
    auto key = make_rsa_key();
    auto certificate = make_certificate(key.get(), 4003, "numeric-sni.test");
    ASSERT_NE(key, nullptr);
    ASSERT_NE(certificate, nullptr);
    ASSERT_TRUE(add_certificate_extension(
        certificate.get(), NID_subject_alt_name, "DNS:192.0.2.81"));
    ASSERT_GT(X509_sign(certificate.get(), key.get(), EVP_sha256()), 0);
    ASSERT_EQ(X509_check_host(certificate.get(), "192.0.2.81", 0, 0, nullptr), 1);
    ASSERT_EQ(X509_check_ip_asc(certificate.get(), "192.0.2.81", 0), 0);

    auto client_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    auto server_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(client_context, nullptr);
    ASSERT_NE(server_context, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate.get()), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), key.get()), 1);

    auto base_tls = make_memory_tls_pair(client_context.get(), server_context.get());
    ASSERT_NE(base_tls.client, nullptr);
    SSLCom_Buddy base_connection;
    base_connection.test_take_ssl(base_tls.client.release());
    EXPECT_FALSE(base_connection.test_check_cert("192.0.2.81"));
    EXPECT_TRUE(base_connection.verify_bitcheck(
        SSLCom::verify_status_t::VRF_HOSTNAME_FAILED));

    auto tls = make_memory_tls_pair(client_context.get(), server_context.get());
    ASSERT_NE(tls.client, nullptr);
    ASSERT_NE(tls.server, nullptr);

    SSLMitmCom_Buddy upstream;
    SSLMitmCom_Buddy downstream;
    upstream.peer(&downstream);
    downstream.peer(&upstream);
    upstream.test_take_ssl(tls.client.release());
    upstream.verify_reset(SSLCom::verify_status_t::VRF_OK);
    upstream.test_sni("192.0.2.81");
    upstream.test_peer_sni_shortcut(true);
    EXPECT_TRUE(upstream.check_cert(nullptr));
    EXPECT_TRUE(upstream.verify_bitcheck(SSLCom::verify_status_t::VRF_HOSTNAME_FAILED));
}

TEST(TLS_Tests, BaseCertificateCheckRejectsHostnameMismatch) {
    auto certificate = load_tls_test_certificate();
    auto key = load_tls_test_key();
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(key, nullptr);

    auto client_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    auto server_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(client_context, nullptr);
    ASSERT_NE(server_context, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate.get()), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), key.get()), 1);

    auto tls = make_memory_tls_pair(client_context.get(), server_context.get());
    ASSERT_NE(tls.client, nullptr);
    ASSERT_NE(tls.server, nullptr);

    SSLCom_Buddy connection;
    connection.test_take_ssl(tls.client.release());
    EXPECT_TRUE(connection.test_check_cert("Smithproxy-Server-Certificate"));
    EXPECT_FALSE(connection.test_check_cert("wrong-hostname.example"));
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_HOSTNAME_FAILED));
}

TEST(TLS_Tests, SniRewriteKeepsOriginalClientIdentityForSpoofedCertificate) {
    auto key = make_rsa_key();
    auto certificate = make_certificate(key.get(), 4002, "origin.internal");
    ASSERT_NE(key, nullptr);
    ASSERT_NE(certificate, nullptr);

    auto client_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    auto server_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(client_context, nullptr);
    ASSERT_NE(server_context, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), certificate.get()), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), key.get()), 1);
    auto tls = make_memory_tls_pair(client_context.get(), server_context.get());
    ASSERT_NE(tls.client, nullptr);
    ASSERT_NE(tls.server, nullptr);

    SSLMitmCom_Buddy upstream;
    SSLMitmCom_Buddy downstream;
    upstream.peer(&downstream);
    downstream.peer(&upstream);
    upstream.test_take_ssl(tls.client.release());
    upstream.verify_reset(SSLCom::verify_status_t::VRF_OK);
    upstream.test_sni("origin.internal");
    downstream.test_sni("client.example");
    downstream.capture_spoof_options = true;
    downstream.upgraded(true);

    ASSERT_TRUE(upstream.check_cert(nullptr));
    ASSERT_TRUE(downstream.captured_spoof_options.has_value());
    EXPECT_EQ(downstream.captured_spoof_options->sni, "client.example");
    EXPECT_NE(std::find(downstream.captured_spoof_options->sans.begin(),
                        downstream.captured_spoof_options->sans.end(),
                        "DNS:client.example"),
              downstream.captured_spoof_options->sans.end());
}

TEST(TLS_Tests, MitmIpValidationUsesTheConnectionDestinationWithoutSni) {
    auto source = load_tls_test_certificate();
    ASSERT_NE(source, nullptr);

    auto& factory = SSLFactory::factory();
    const std::string saved_certs_path = factory.certs_path();
    const std::string saved_password = factory.certs_password();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    factory.destroy();
    factory.certs_path() = "etc/certs/default/";
    factory.certs_password() = "smithproxy";
    factory.ca_file() = "etc/certs/default/ca-cert.pem";
    factory.ca_path().clear();
    auto restore_factory = raw::guard([&] {
        factory.destroy();
        factory.certs_path() = saved_certs_path;
        factory.certs_password() = saved_password;
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
    });
    ASSERT_TRUE(factory.load_from_files());
    std::vector<std::string> ip_sans {"IP:192.0.2.8"};
    auto generated = factory.spoof(source.get(), false, &ip_sans);
    ASSERT_TRUE(generated.has_value());
    ASSERT_NE(generated->chain.cert, nullptr);
    ASSERT_NE(generated->chain.key, nullptr);
    ASSERT_EQ(X509_check_ip_asc(generated->chain.cert, "192.0.2.8", 0), 1);

    auto client_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    auto server_context = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(client_context, nullptr);
    ASSERT_NE(server_context, nullptr);
    SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);
    ASSERT_EQ(SSL_CTX_use_certificate(server_context.get(), generated->chain.cert), 1);
    ASSERT_EQ(SSL_CTX_use_PrivateKey(server_context.get(), generated->chain.key), 1);

    auto check_address = [&](char const* address) {
        auto tls = make_memory_tls_pair(client_context.get(), server_context.get());
        EXPECT_NE(tls.client, nullptr);
        EXPECT_NE(tls.server, nullptr);

        SSLMitmCom_Buddy upstream;
        baseHostCX upstream_context(new TCPCom, address, "443");
        upstream.owner_cx_ = &upstream_context;
        SSLMitmCom_Buddy downstream;
        upstream.peer(&downstream);
        downstream.peer(&upstream);
        upstream.test_take_ssl(tls.client.release());
        upstream.verify_reset(SSLCom::verify_status_t::VRF_OK);
        upstream.test_peer_sni_shortcut(true);
        EXPECT_TRUE(upstream.check_cert(nullptr));
        upstream.owner_cx_ = nullptr;
        return upstream.verify_bitcheck(SSLCom::verify_status_t::VRF_HOSTNAME_FAILED);
    };

    EXPECT_FALSE(check_address("192.0.2.8"));
    EXPECT_TRUE(check_address("192.0.2.9"));

    X509_free(generated->chain.cert);
    generated->nullify(); // spoof() lends the factory-owned server key.
}

TEST(TLS_Tests, OpenSslCallbacksFailClosedDuringPartialInitialization) {
    EXPECT_EQ(SSLCom::server_get_session_callback(nullptr, nullptr, 0, nullptr), nullptr);
    EXPECT_EQ(SSLCom::new_session_callback(nullptr, nullptr), 0);
    EXPECT_EQ(SSLCom::status_resp_callback(nullptr, nullptr), -1);
    EXPECT_EQ(SSLCom::ssl_client_cert_callback(nullptr, nullptr, nullptr), 0);
    EXPECT_EQ(SSLCom::ct_verify_callback(nullptr, nullptr, nullptr), 0);
    const auto missing_staple = SSLCom::check_revocation_stapling(
        "partial", nullptr, nullptr);
    EXPECT_EQ(missing_staple.first, SSLCom::staple_code_t::NOT_PROCESSED);
    EXPECT_EQ(missing_staple.second, -1);

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(context, nullptr);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context.get()), SSL_free);
    ASSERT_NE(ssl, nullptr);

    const unsigned char* selected = nullptr;
    unsigned char selected_length = 0;
    EXPECT_EQ(SSLCom::ssl_alpn_select_callback(
                  nullptr, &selected, &selected_length, nullptr, 0, nullptr),
              SSL_TLSEXT_ERR_NOACK);
    EXPECT_EQ(SSLCom::ssl_alpn_select_callback(
                  ssl.get(), &selected, &selected_length, nullptr, 0, nullptr),
              SSL_TLSEXT_ERR_NOACK);
    EXPECT_EQ(SSLCom::status_resp_callback(ssl.get(), nullptr), -1);

    X509* certificate = reinterpret_cast<X509*>(1);
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(1);
    EXPECT_EQ(SSLCom::ssl_client_cert_callback(
                  ssl.get(), &certificate, &key), 0);
    EXPECT_EQ(certificate, nullptr);
    EXPECT_EQ(key, nullptr);

    SSLCom_Buddy downstream;
    SSLCom_Buddy upstream;
    downstream.peer(&upstream);
    ASSERT_EQ(SSL_set_ex_data(ssl.get(), SSLCom::extdata_index(), &downstream), 1);
    // The downstream callback may run before the upstream side has created
    // its SSL object. That ordering must not dereference the partial peer.
    EXPECT_EQ(SSLCom::ssl_alpn_select_callback(
                  ssl.get(), &selected, &selected_length, nullptr, 0, nullptr),
              SSL_TLSEXT_ERR_NOACK);
}

TEST(TLS_Tests, DisabledOcspCannotEraseCertificateVerificationFailure) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(context, nullptr);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context.get()), SSL_free);
    ASSERT_NE(ssl, nullptr);
    SSLCom_Buddy connection;
    ASSERT_EQ(SSL_set_ex_data(ssl.get(), SSLCom::extdata_index(), &connection), 1);

    connection.opt.ocsp.stapling_enabled = false;
    connection.opt.ocsp.mode = 0;
    connection.verify_reset(SSLCom::verify_status_t::VRF_INVALID);
    EXPECT_EQ(SSLCom::status_resp_callback(ssl.get(), nullptr), 1);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_INVALID));
    EXPECT_FALSE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_OK));
    EXPECT_EQ(connection.verify_origin(), SSLCom::verify_origin_t::NONE);

    connection.verify_reset(SSLCom::verify_status_t::VRF_NOTTESTED);
    EXPECT_EQ(SSLCom::status_resp_callback(ssl.get(), nullptr), 1);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_NOTTESTED));
    EXPECT_FALSE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_OK));
}

TEST(TLS_Tests, RevocationCallbacksHandleMissingCertificateState) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(context, nullptr);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context.get()), SSL_free);
    ASSERT_NE(ssl, nullptr);
    SSLCom_Buddy connection;
    ASSERT_EQ(SSL_set_ex_data(ssl.get(), SSLCom::extdata_index(), &connection), 1);

    connection.opt.ocsp.stapling_enabled = true;
    connection.opt.ocsp.stapling_mode = 2;
    connection.opt.cert.failed_check_replacement = false;
    connection.verify_reset(SSLCom::verify_status_t::VRF_NOTTESTED);
    EXPECT_EQ(SSLCom::status_resp_callback(ssl.get(), nullptr), 0);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_ALLFAILED));

    connection.opt.ocsp.enforce_in_verify = false;
    const auto missing = SSLCom::check_revocation_stapling(
        "missing", &connection, ssl.get());
    EXPECT_EQ(missing.first, SSLCom::staple_code_t::MISSING_BODY);
    EXPECT_EQ(missing.second, -1);
    EXPECT_TRUE(connection.opt.ocsp.enforce_in_verify);

    connection.verify_reset(SSLCom::verify_status_t::VRF_NOTTESTED);
    connection.opt.cert.failed_check_replacement = true;
    EXPECT_EQ(SSLCom::certificate_status_oob_check(&connection, 0), 1);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_ALLFAILED));
    EXPECT_EQ(SSLCom::certificate_status_oob_check(nullptr, 7), 7);
}

TEST(TLS_Tests, StaplingParserClassifiesMalformedAndIncompleteResponses) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(context, nullptr);
    SSLCom_Buddy connection;
    connection.opt.ocsp.stapling_mode = 2;

    auto check = [&](unsigned char* body, int length) {
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
            SSL_new(context.get()), SSL_free);
        EXPECT_NE(ssl, nullptr);
        EXPECT_EQ(SSL_set_tlsext_status_ocsp_resp(ssl.get(), body, length), 1);
        ERR_clear_error();
        const auto result = SSLCom::check_revocation_stapling(
            "test", &connection, ssl.get());
        EXPECT_EQ(ERR_peek_error(), 0UL);
        return result;
    };

    auto* malformed = static_cast<unsigned char*>(OPENSSL_malloc(3));
    ASSERT_NE(malformed, nullptr);
    malformed[0] = 0xff;
    malformed[1] = 0x00;
    malformed[2] = 0x01;
    auto result = check(malformed, 3);
    EXPECT_EQ(result.first, SSLCom::staple_code_t::PARSING_FAILED);

    auto encode = [](int status) {
        std::unique_ptr<OCSP_RESPONSE, decltype(&OCSP_RESPONSE_free)> response(
            OCSP_response_create(status, nullptr), OCSP_RESPONSE_free);
        unsigned char* encoded = nullptr;
        const int length = response ? i2d_OCSP_RESPONSE(response.get(), &encoded) : -1;
        return std::pair<unsigned char*, int>{encoded, length};
    };

    auto retry = encode(OCSP_RESPONSE_STATUS_TRYLATER);
    ASSERT_NE(retry.first, nullptr);
    ASSERT_GT(retry.second, 0);
    result = check(retry.first, retry.second);
    EXPECT_EQ(result.first, SSLCom::staple_code_t::STATUS_NOK);
    EXPECT_EQ(result.second, OCSP_RESPONSE_STATUS_TRYLATER);

    auto trailing = encode(OCSP_RESPONSE_STATUS_TRYLATER);
    ASSERT_NE(trailing.first, nullptr);
    ASSERT_GT(trailing.second, 0);
    auto* trailing_body = static_cast<unsigned char*>(
        OPENSSL_malloc(static_cast<std::size_t>(trailing.second) + 1));
    ASSERT_NE(trailing_body, nullptr);
    std::memcpy(trailing_body, trailing.first,
                static_cast<std::size_t>(trailing.second));
    trailing_body[trailing.second] = 0x00;
    OPENSSL_free(trailing.first);
    result = check(trailing_body, trailing.second + 1);
    EXPECT_EQ(result.first, SSLCom::staple_code_t::PARSING_FAILED);

    auto incomplete = encode(OCSP_RESPONSE_STATUS_SUCCESSFUL);
    ASSERT_NE(incomplete.first, nullptr);
    ASSERT_GT(incomplete.second, 0);
    result = check(incomplete.first, incomplete.second);
    EXPECT_EQ(result.first, SSLCom::staple_code_t::GET_BASIC_FAILED);
    EXPECT_EQ(result.second, OCSP_RESPONSE_STATUS_SUCCESSFUL);
}

TEST(TLS_Tests, StapledOcspGoodRevokedAndStaleResponsesDrivePolicyState) {
    init_log();
    auto issuer_key = make_rsa_key();
    auto certificate_key = make_rsa_key();
    auto issuer = make_certificate(issuer_key.get(), 4101, "Stapling test CA");
    auto certificate = make_certificate(
        certificate_key.get(), 4102, "stapled.example.test",
        issuer.get(), issuer_key.get());
    ASSERT_NE(issuer_key, nullptr);
    ASSERT_NE(certificate_key, nullptr);
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);

    auto& factory = SSLFactory::factory();
    const std::string saved_certs_path = factory.certs_path();
    const std::string saved_password = factory.certs_password();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    factory.destroy();
    factory.certs_path() = "etc/certs/default/";
    factory.certs_password() = "smithproxy";
    factory.ca_file() = "etc/certs/default/ca-cert.pem";
    factory.ca_path().clear();
    auto restore_factory = raw::guard([&] {
        factory.destroy();
        factory.certs_path() = saved_certs_path;
        factory.certs_password() = saved_password;
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
    });
    ASSERT_TRUE(factory.load_from_files());
    ASSERT_TRUE(factory.load_trust_store());
    ASSERT_EQ(X509_STORE_add_cert(factory.trust_store(), issuer.get()), 1);

    auto exercise = [&](int status, long this_update, long next_update,
                        SSLCom::staple_code_t expected_code,
                        int expected_callback, SSLCom::verify_status_t expected_flag,
                        int duplicate_status = -1,
                        bool omit_next_update = false) {
        auto response = make_ocsp_response(
            certificate.get(), issuer.get(), issuer_key.get(), status,
            this_update, next_update, nullptr, duplicate_status,
            omit_next_update);
        ASSERT_NE(response, nullptr);
        unsigned char* encoded = nullptr;
        const int encoded_length = i2d_OCSP_RESPONSE(response.get(), &encoded);
        ASSERT_GT(encoded_length, 0);
        ASSERT_NE(encoded, nullptr);

        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
            SSL_CTX_new(TLS_method()), SSL_CTX_free);
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
            SSL_new(context.get()), SSL_free);
        ASSERT_NE(context, nullptr);
        ASSERT_NE(ssl, nullptr);
        ASSERT_EQ(SSL_set_tlsext_status_ocsp_resp(
                      ssl.get(), encoded, encoded_length), 1);

        SSLCom_Buddy connection;
        connection.factory(&factory);
        connection.test_peer_chain(certificate.get(), issuer.get());
        connection.opt.ocsp.stapling_enabled = true;
        connection.opt.ocsp.stapling_mode = 2;
        connection.opt.cert.failed_check_replacement = false;
        ASSERT_EQ(SSL_set_ex_data(
                      ssl.get(), SSLCom::extdata_index(), &connection), 1);

        const auto parsed = SSLCom::check_revocation_stapling(
            "stapled-ocsp-test", &connection, ssl.get());
        EXPECT_EQ(parsed.first, expected_code);
        EXPECT_EQ(SSLCom::status_resp_callback(ssl.get(), nullptr),
                  expected_callback);
        EXPECT_TRUE(connection.verify_bitcheck(expected_flag));
    };

    exercise(V_OCSP_CERTSTATUS_GOOD, -60, 3600,
             SSLCom::staple_code_t::SUCCESS, 1,
             SSLCom::verify_status_t::VRF_OK);
    exercise(V_OCSP_CERTSTATUS_REVOKED, -60, 3600,
             SSLCom::staple_code_t::SUCCESS, 0,
             SSLCom::verify_status_t::VRF_REVOKED);
    exercise(V_OCSP_CERTSTATUS_GOOD, -7200, -3600,
             SSLCom::staple_code_t::INVALID_TIME, 0,
             SSLCom::verify_status_t::VRF_ALLFAILED);
    exercise(V_OCSP_CERTSTATUS_GOOD, -60, 3600,
             SSLCom::staple_code_t::NO_FIND_STATUS, 0,
             SSLCom::verify_status_t::VRF_ALLFAILED,
             V_OCSP_CERTSTATUS_REVOKED);
    exercise(V_OCSP_CERTSTATUS_GOOD, -60, 0,
             SSLCom::staple_code_t::SUCCESS, 1,
             SSLCom::verify_status_t::VRF_OK,
             -1, true);
    exercise(V_OCSP_CERTSTATUS_GOOD, -7200, 0,
             SSLCom::staple_code_t::INVALID_TIME, 0,
             SSLCom::verify_status_t::VRF_ALLFAILED,
             -1, true);
}

TEST(TLS_Tests, FullChainOcspModeContinuesAfterGoodLeafStaple) {
    init_log();
    auto root_key = make_rsa_key();
    auto intermediate_key = make_rsa_key();
    auto leaf_key = make_rsa_key();
    auto root = make_certificate(root_key.get(), 4151, "Stapling root CA");
    auto intermediate = make_certificate(
        intermediate_key.get(), 4152, "Stapling intermediate CA",
        root.get(), root_key.get());
    auto leaf = make_certificate(
        leaf_key.get(), 4153, "stapled-chain.example.test",
        intermediate.get(), intermediate_key.get());
    ASSERT_NE(root, nullptr);
    ASSERT_NE(intermediate, nullptr);
    ASSERT_NE(leaf, nullptr);

    auto& factory = SSLFactory::factory();
    const std::string saved_certs_path = factory.certs_path();
    const std::string saved_password = factory.certs_password();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    factory.destroy();
    factory.certs_path() = "etc/certs/default/";
    factory.certs_password() = "smithproxy";
    factory.ca_file() = "etc/certs/default/ca-cert.pem";
    factory.ca_path().clear();
    auto restore_factory = raw::guard([&] {
        factory.destroy();
        factory.certs_path() = saved_certs_path;
        factory.certs_password() = saved_password;
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
    });
    ASSERT_TRUE(factory.load_from_files());
    ASSERT_TRUE(factory.load_trust_store());
    ASSERT_EQ(X509_STORE_add_cert(factory.trust_store(), root.get()), 1);

    auto response = make_ocsp_response(
        leaf.get(), intermediate.get(), intermediate_key.get(),
        V_OCSP_CERTSTATUS_GOOD, -60, 3600);
    ASSERT_NE(response, nullptr);
    unsigned char* encoded = nullptr;
    const int encoded_length = i2d_OCSP_RESPONSE(response.get(), &encoded);
    ASSERT_GT(encoded_length, 0);
    ASSERT_NE(encoded, nullptr);

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
        SSL_new(context.get()), SSL_free);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(ssl, nullptr);
    ASSERT_EQ(SSL_set_tlsext_status_ocsp_resp(
                  ssl.get(), encoded, encoded_length), 1);

    const std::string leaf_cache_key = SSLFactory::print_cn(leaf.get()) + ";" +
                                       SSLFactory::fingerprint(leaf.get());
    const std::string intermediate_cache_key =
        SSLFactory::print_cn(intermediate.get()) + ";" +
        SSLFactory::fingerprint(intermediate.get());
    factory.verify_cache().erase(leaf_cache_key);
    factory.verify_cache().erase(intermediate_cache_key);
    factory.verify_cache().set(
        intermediate_cache_key, SSLFactory::make_exp_ocsp_status(1, 60));
    auto cleanup_cache = raw::guard([&] {
        factory.verify_cache().erase(leaf_cache_key);
        factory.verify_cache().erase(intermediate_cache_key);
    });

    SSLCom_Buddy connection;
    connection.factory(&factory);
    connection.test_peer_chain_three(
        leaf.get(), intermediate.get(), root.get());
    connection.opt.ocsp.stapling_enabled = true;
    connection.opt.ocsp.stapling_mode = 2;
    connection.opt.ocsp.mode = 2;
    connection.opt.cert.failed_check_replacement = false;
    connection.verify_reset(SSLCom::verify_status_t::VRF_OK);
    ASSERT_EQ(SSL_set_ex_data(
                  ssl.get(), SSLCom::extdata_index(), &connection), 1);

    EXPECT_EQ(SSLCom::status_resp_callback(ssl.get(), nullptr), 0);
    EXPECT_TRUE(connection.verify_bitcheck(
        SSLCom::verify_status_t::VRF_REVOKED));
    EXPECT_FALSE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_OK));
    EXPECT_EQ(factory.verify_cache().get(leaf_cache_key), nullptr);

    factory.verify_cache().erase(intermediate_cache_key);
    factory.verify_cache().set(
        intermediate_cache_key, SSLFactory::make_exp_ocsp_status(-1, 60));
    SSLCom_Buddy unknown_connection;
    unknown_connection.factory(&factory);
    unknown_connection.test_peer_chain_three(
        leaf.get(), intermediate.get(), root.get());
    unknown_connection.opt.ocsp.stapling_enabled = true;
    unknown_connection.opt.ocsp.stapling_mode = 2;
    unknown_connection.opt.ocsp.mode = 2;
    unknown_connection.opt.cert.failed_check_replacement = false;
    unknown_connection.verify_reset(SSLCom::verify_status_t::VRF_OK);
    ASSERT_EQ(SSL_set_ex_data(
                  ssl.get(), SSLCom::extdata_index(), &unknown_connection), 1);
    EXPECT_EQ(SSLCom::status_resp_callback(ssl.get(), nullptr), 0);
    EXPECT_TRUE(unknown_connection.verify_bitcheck(
        SSLCom::verify_status_t::VRF_ALLFAILED));
    EXPECT_FALSE(unknown_connection.verify_bitcheck(
        SSLCom::verify_status_t::VRF_OK));
}

TEST(TLS_Tests, CachedOcspResultPreservesGoodRevokedAndUnknownSemantics) {
    init_log();
    auto issuer_key = make_rsa_key();
    auto certificate_key = make_rsa_key();
    auto issuer = make_certificate(issuer_key.get(), 4201, "Cached OCSP test CA");
    auto certificate = make_certificate(
        certificate_key.get(), 4202, "cached-ocsp.example.test",
        issuer.get(), issuer_key.get());
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(certificate, nullptr);

    auto& factory = SSLFactory::factory();
    const std::string cache_key = SSLFactory::print_cn(certificate.get()) + ";" +
                                  SSLFactory::fingerprint(certificate.get());
    auto cleanup = raw::guard([&] { factory.verify_cache().erase(cache_key); });

    auto exercise = [&](int cached_result, int expected_result,
                        SSLCom::verify_status_t expected_flag,
                        bool expect_ok) {
        factory.verify_cache().erase(cache_key);
        factory.verify_cache().set(
            cache_key, SSLFactory::make_exp_ocsp_status(cached_result, 60));

        SSLCom_Buddy connection;
        connection.factory(&factory);
        connection.test_peer_chain(certificate.get(), issuer.get());
        connection.verify_reset(SSLCom::verify_status_t::VRF_OK);

        EXPECT_EQ(SSLCom::certificate_status_ocsp_check(&connection),
                  expected_result);
        EXPECT_EQ(connection.verify_origin(),
                  SSLCom::verify_origin_t::OCSP_CACHE);
        EXPECT_TRUE(connection.verify_bitcheck(expected_flag));
        EXPECT_EQ(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_OK),
                  expect_ok);
    };

    exercise(0, 0, SSLCom::verify_status_t::VRF_OK, true);
    exercise(1, 1, SSLCom::verify_status_t::VRF_REVOKED, false);
    exercise(-1, -1, SSLCom::verify_status_t::VRF_DEFERRED, false);
}

TEST(TLS_Tests, FullChainOcspModeChecksIntermediateRevocation) {
    init_log();
    auto root_key = make_rsa_key();
    auto intermediate_key = make_rsa_key();
    auto leaf_key = make_rsa_key();
    auto root = make_certificate(root_key.get(), 4251, "OCSP chain root");
    auto intermediate = make_certificate(
        intermediate_key.get(), 4252, "OCSP chain intermediate",
        root.get(), root_key.get());
    auto leaf = make_certificate(
        leaf_key.get(), 4253, "OCSP chain leaf",
        intermediate.get(), intermediate_key.get());
    ASSERT_NE(root, nullptr);
    ASSERT_NE(intermediate, nullptr);
    ASSERT_NE(leaf, nullptr);

    auto& factory = SSLFactory::factory();
    const std::string leaf_key_string = SSLFactory::print_cn(leaf.get()) + ";" +
                                        SSLFactory::fingerprint(leaf.get());
    const std::string intermediate_key_string =
        SSLFactory::print_cn(intermediate.get()) + ";" +
        SSLFactory::fingerprint(intermediate.get());
    auto cleanup = raw::guard([&] {
        factory.verify_cache().erase(leaf_key_string);
        factory.verify_cache().erase(intermediate_key_string);
    });

    auto seed_cache = [&] {
        factory.verify_cache().erase(leaf_key_string);
        factory.verify_cache().erase(intermediate_key_string);
        factory.verify_cache().set(
            leaf_key_string, SSLFactory::make_exp_ocsp_status(0, 60));
        factory.verify_cache().set(
            intermediate_key_string, SSLFactory::make_exp_ocsp_status(1, 60));
    };
    auto exercise = [&](int mode) {
        seed_cache();
        SSLCom_Buddy connection;
        connection.factory(&factory);
        connection.test_peer_chain_three(
            leaf.get(), intermediate.get(), root.get());
        connection.opt.ocsp.mode = mode;
        connection.verify_reset(SSLCom::verify_status_t::VRF_OK);
        return std::pair<int, int>{
            SSLCom::certificate_status_ocsp_check(&connection),
            connection.verify_get()};
    };

    const auto leaf_only = exercise(1);
    EXPECT_EQ(leaf_only.first, 0);
    EXPECT_EQ(leaf_only.second, SSLCom::verify_status_t::VRF_OK);

    const auto full_chain = exercise(2);
    EXPECT_EQ(full_chain.first, 1);
    EXPECT_TRUE(static_cast<unsigned int>(full_chain.second) &
                SSLCom::verify_status_t::VRF_REVOKED);
    EXPECT_FALSE(static_cast<unsigned int>(full_chain.second) &
                 SSLCom::verify_status_t::VRF_OK);

    factory.verify_cache().erase(leaf_key_string);
    factory.verify_cache().set(
        leaf_key_string, SSLFactory::make_exp_ocsp_status(0, 60));
    SSLCom_Buddy incomplete_chain;
    incomplete_chain.factory(&factory);
    incomplete_chain.test_peer_chain(leaf.get(), intermediate.get());
    incomplete_chain.opt.ocsp.mode = 2;
    incomplete_chain.verify_reset(SSLCom::verify_status_t::VRF_OK);
    EXPECT_EQ(SSLCom::certificate_status_ocsp_check(&incomplete_chain), -1);
    EXPECT_TRUE(incomplete_chain.verify_bitcheck(
        SSLCom::verify_status_t::VRF_DEFERRED));
    EXPECT_FALSE(incomplete_chain.verify_bitcheck(
        SSLCom::verify_status_t::VRF_OK));
}

TEST(TLS_Tests, CachedCrlFallbackUsesConfiguredCaDirectory) {
    init_log();
    constexpr const char* crl_url = "http://crl.example.test/cached.crl";
    auto issuer_key = make_rsa_key();
    auto unrelated_issuer_key = make_rsa_key();
    auto certificate_key = make_rsa_key();
    auto issuer = make_certificate(issuer_key.get(), 4301, "CRL fallback test CA");
    auto unrelated_issuer = make_certificate(
        unrelated_issuer_key.get(), 4303, "Unrelated CRL cache CA");
    auto certificate = make_certificate(
        certificate_key.get(), 4302, "crl-fallback.example.test",
        issuer.get(), issuer_key.get());
    ASSERT_NE(issuer, nullptr);
    ASSERT_NE(unrelated_issuer, nullptr);
    ASSERT_NE(certificate, nullptr);
    ASSERT_TRUE(add_certificate_extension(
        certificate.get(), NID_crl_distribution_points,
        "URI:http://crl.example.test/cached.crl"));
    ASSERT_GT(X509_sign(certificate.get(), issuer_key.get(), EVP_sha256()), 0);

    auto current = make_test_crl(issuer.get(), issuer_key.get());
    auto revoked = make_test_crl(
        issuer.get(), issuer_key.get(), certificate.get());
    auto unrelated = make_test_crl(
        unrelated_issuer.get(), unrelated_issuer_key.get());
    ASSERT_NE(current, nullptr);
    ASSERT_NE(revoked, nullptr);
    ASSERT_NE(unrelated, nullptr);

    const std::filesystem::path ca_directory =
        std::filesystem::temp_directory_path() /
        ("smithproxy-crl-fallback-ca-" + std::to_string(::getpid()));
    std::filesystem::remove_all(ca_directory);
    std::filesystem::create_directories(ca_directory);
    char hashed_name[32] {};
    std::snprintf(hashed_name, sizeof(hashed_name), "%08lx.0",
                  X509_NAME_hash(X509_get_subject_name(issuer.get())));
    FILE* output = std::fopen((ca_directory / hashed_name).c_str(), "w");
    ASSERT_NE(output, nullptr);
    ASSERT_EQ(PEM_write_X509(output, issuer.get()), 1);
    std::fclose(output);

    auto& factory = SSLFactory::factory();
    const std::string saved_ca_path = factory.ca_path();
    const std::string verify_key = SSLFactory::print_cn(certificate.get()) + ";" +
                                   SSLFactory::fingerprint(certificate.get());
    const std::string crl_cache_key = std::string(crl_url) + ";issuer=" +
                                      SSLFactory::fingerprint(issuer.get());
    auto cleanup = raw::guard([&] {
        factory.ca_path() = saved_ca_path;
        factory.verify_cache().erase(verify_key);
        factory.crl_cache().erase(crl_url);
        factory.crl_cache().erase(crl_cache_key);
        std::filesystem::remove_all(ca_directory);
    });
    factory.ca_path() = ca_directory.string();

    auto exercise = [&](X509_CRL* crl, int expected_result,
                        SSLCom::verify_status_t expected_flag, bool expect_ok) {
        factory.verify_cache().erase(verify_key);
        factory.verify_cache().set(
            verify_key, SSLFactory::make_exp_ocsp_status(-1, 60));
        factory.crl_cache().erase(crl_cache_key);
        ASSERT_EQ(X509_CRL_up_ref(crl), 1);
        factory.crl_cache().set(
            crl_cache_key, SSLFactory::make_expiring_crl(crl));

        SSLCom_Buddy connection;
        connection.factory(&factory);
        connection.test_peer_chain(certificate.get(), issuer.get());
        connection.verify_reset(SSLCom::verify_status_t::VRF_OK);

        EXPECT_EQ(SSLCom::certificate_status_ocsp_check(&connection),
                  expected_result);
        EXPECT_EQ(connection.verify_origin(),
                  SSLCom::verify_origin_t::CRL_CACHE);
        EXPECT_TRUE(connection.verify_bitcheck(expected_flag));
        EXPECT_EQ(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_OK),
                  expect_ok);
    };

    // A legacy URL-only entry belonging to another CA must not shadow the
    // issuer-scoped CRL selected below.
    ASSERT_EQ(X509_CRL_up_ref(unrelated.get()), 1);
    factory.crl_cache().set(
        crl_url, SSLFactory::make_expiring_crl(unrelated.get()));

    exercise(current.get(), 0, SSLCom::verify_status_t::VRF_OK, true);
    exercise(revoked.get(), 1, SSLCom::verify_status_t::VRF_REVOKED, false);
}

TEST(TLS_Tests, VerificationOptionMaskRequiresEveryFailureToBeAllowed) {
    SSLCom_Buddy connection;
    connection.opt.cert.allow_self_signed = true;
    connection.verify_reset(static_cast<SSLCom::verify_status_t>(
        SSLCom::verify_status_t::VRF_SELF_SIGNED |
        SSLCom::verify_status_t::VRF_DEFERRED));
    EXPECT_TRUE(connection.is_verify_status_opt_allowed());

    connection.verify_reset(static_cast<SSLCom::verify_status_t>(
        SSLCom::verify_status_t::VRF_SELF_SIGNED |
        SSLCom::verify_status_t::VRF_UNKNOWN_ISSUER));
    EXPECT_FALSE(connection.is_verify_status_opt_allowed());
    connection.opt.cert.allow_unknown_issuer = true;
    EXPECT_TRUE(connection.is_verify_status_opt_allowed());

    EXPECT_EQ(SSLCom::verify_origin_str(SSLCom::verify_origin_t::NONE), "none");
    EXPECT_EQ(SSLCom::verify_origin_str(SSLCom::verify_origin_t::OCSP_STAPLING),
              "ocsp stapling");
    EXPECT_EQ(SSLCom::verify_origin_str(SSLCom::verify_origin_t::OCSP_CACHE),
              "ocsp cache");
    EXPECT_EQ(SSLCom::verify_origin_str(SSLCom::verify_origin_t::OCSP), "ocsp");
    EXPECT_EQ(SSLCom::verify_origin_str(SSLCom::verify_origin_t::CRL_CACHE),
              "crl cache");
    EXPECT_EQ(SSLCom::verify_origin_str(SSLCom::verify_origin_t::CRL), "crl");
    EXPECT_EQ(SSLCom::verify_origin_str(SSLCom::verify_origin_t::EXEMPT), "<?>");
}

TEST(TLS_Tests, OpenSslVerifyCallbackMapsFailuresAndHonorsOnlyMatchingExceptions) {
    init_log();
    auto certificate = load_tls_test_certificate();
    ASSERT_NE(certificate, nullptr);

    auto exercise = [&](int error, SSLCom::verify_status_t expected_status,
                        auto configure, int expected_result) {
        std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ssl_context(
            SSL_CTX_new(TLS_method()), SSL_CTX_free);
        std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
            SSL_new(ssl_context.get()), SSL_free);
        std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(
            X509_STORE_new(), X509_STORE_free);
        std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> verify_context(
            X509_STORE_CTX_new(), X509_STORE_CTX_free);
        ASSERT_NE(ssl_context, nullptr);
        ASSERT_NE(ssl, nullptr);
        ASSERT_NE(store, nullptr);
        ASSERT_NE(verify_context, nullptr);
        ASSERT_EQ(X509_STORE_CTX_init(
                      verify_context.get(), store.get(), certificate.get(), nullptr), 1);
        X509_STORE_CTX_set_current_cert(verify_context.get(), certificate.get());

        SSLCom_Buddy connection;
        configure(connection);
        ASSERT_EQ(SSL_set_ex_data(
                      ssl.get(), SSLCom::extdata_index(), &connection), 1);
        ASSERT_EQ(X509_STORE_CTX_set_ex_data(
                      verify_context.get(), SSL_get_ex_data_X509_STORE_CTX_idx(),
                      ssl.get()), 1);
        X509_STORE_CTX_set_error(verify_context.get(), error);
        X509_STORE_CTX_set_error_depth(verify_context.get(), 0);

        EXPECT_EQ(SSLCom::ssl_client_vrfy_callback(0, verify_context.get()),
                  expected_result);
        EXPECT_TRUE(connection.verify_bitcheck(expected_status));
    };

    const auto strict = [](SSLCom_Buddy& connection) {
        connection.opt.cert.failed_check_replacement = false;
    };
    exercise(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
             SSLCom::verify_status_t::VRF_UNKNOWN_ISSUER, strict, 0);
    exercise(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
             SSLCom::verify_status_t::VRF_UNKNOWN_ISSUER,
             [](SSLCom_Buddy& connection) {
                 connection.opt.cert.failed_check_replacement = false;
                 connection.opt.cert.allow_unknown_issuer = true;
             }, 1);
    exercise(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT,
             SSLCom::verify_status_t::VRF_SELF_SIGNED,
             [](SSLCom_Buddy& connection) {
                 connection.opt.cert.failed_check_replacement = false;
                 connection.opt.cert.allow_self_signed = true;
             }, 1);
    exercise(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN,
             SSLCom::verify_status_t::VRF_SELF_SIGNED_CHAIN,
             [](SSLCom_Buddy& connection) {
                 connection.opt.cert.failed_check_replacement = false;
                 connection.opt.cert.allow_self_signed_chain = true;
             }, 1);
    exercise(X509_V_ERR_CERT_HAS_EXPIRED,
             SSLCom::verify_status_t::VRF_INVALID,
             [](SSLCom_Buddy& connection) {
                 connection.opt.cert.failed_check_replacement = false;
                 connection.opt.cert.allow_not_valid = true;
             }, 1);
    exercise(X509_V_ERR_CERT_REVOKED,
             SSLCom::verify_status_t::VRF_INVALID,
             [](SSLCom_Buddy& connection) {
                 // An unrelated exception must never make another failure pass.
                 connection.opt.cert.failed_check_replacement = false;
                 connection.opt.cert.allow_self_signed = true;
             }, 0);
    exercise(X509_V_ERR_CERT_REVOKED,
             SSLCom::verify_status_t::VRF_INVALID,
             [](SSLCom_Buddy& connection) {
                 // Date exceptions must not forgive revocation or structural
                 // certificate errors handled by the catch-all branch.
                 connection.opt.cert.failed_check_replacement = false;
                 connection.opt.cert.allow_not_valid = true;
             }, 0);
    exercise(X509_V_ERR_CERT_REVOKED,
             SSLCom::verify_status_t::VRF_INVALID,
             [](SSLCom_Buddy& connection) {
                 connection.opt.cert.failed_check_replacement = true;
             }, 1);
    exercise(X509_V_ERR_NO_EXPLICIT_POLICY,
             SSLCom::verify_status_t::VRF_INVALID, strict, 0);
    exercise(X509_V_ERR_NO_EXPLICIT_POLICY,
             SSLCom::verify_status_t::VRF_INVALID,
             [](SSLCom_Buddy& connection) {
                 connection.opt.cert.failed_check_replacement = true;
             }, 1);
}

TEST(TLS_Tests, ValidationErrorAllowListAndCachedAlpnAreExact) {
    SSLCom_Buddy connection;
    for (int error : {X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY,
                      X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE,
                      X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT}) {
        EXPECT_FALSE(connection.is_cert_validation_err_code_allowed_by_options(error));
    }
    connection.opt.cert.allow_unknown_issuer = true;
    EXPECT_TRUE(connection.is_cert_validation_err_code_allowed_by_options(
        X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT));

    connection.opt.cert.allow_self_signed_chain = true;
    EXPECT_TRUE(connection.is_cert_validation_err_code_allowed_by_options(
        X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN));
    EXPECT_TRUE(connection.is_cert_validation_err_code_allowed_by_options(
        X509_V_ERR_CERT_UNTRUSTED));
    connection.opt.cert.allow_self_signed = true;
    EXPECT_TRUE(connection.is_cert_validation_err_code_allowed_by_options(
        X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT));
    connection.opt.cert.allow_not_valid = true;
    for (int error : {X509_V_ERR_CERT_NOT_YET_VALID,
                      X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD,
                      X509_V_ERR_CERT_HAS_EXPIRED,
                      X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD}) {
        EXPECT_TRUE(connection.is_cert_validation_err_code_allowed_by_options(error));
    }
    EXPECT_FALSE(connection.is_cert_validation_err_code_allowed_by_options(
        X509_V_ERR_CERT_REVOKED));

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context.get()), SSL_free);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(ssl, nullptr);
    SSLCom_Buddy peer;
    connection.peer(&peer);
    connection.test_alpn("h2");
    ASSERT_EQ(SSL_set_ex_data(ssl.get(), SSLCom::extdata_index(), &connection), 1);
    const unsigned char* selected = nullptr;
    unsigned char selected_length = 0;
    EXPECT_EQ(SSLCom::ssl_alpn_select_callback(
                  ssl.get(), &selected, &selected_length, nullptr, 0, nullptr),
              SSL_TLSEXT_ERR_OK);
    ASSERT_NE(selected, nullptr);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(selected), selected_length), "h2");
    EXPECT_NE(connection.test_flags().find(":ssl<a>"), std::string::npos);
}

TEST(TLS_Tests, CertificateValidationHelpersRejectIncompleteInputsSafely) {
    EXPECT_TRUE(inet::crl::crl_urls(nullptr).empty());
    EXPECT_EQ(inet::crl::crl_from_bytes(static_cast<const char*>(nullptr)), nullptr);
    EXPECT_EQ(inet::crl::crl_from_bytes("not-a-der-crl"), nullptr);
    buffer empty;
    EXPECT_EQ(inet::crl::crl_from_bytes(empty), nullptr);
    EXPECT_EQ(inet::crl::crl_from_file(nullptr), nullptr);
    EXPECT_EQ(inet::crl::crl_from_file("/definitely/missing/crl"), nullptr);
    EXPECT_EQ(inet::crl::crl_verify_trust(nullptr, nullptr, nullptr, {}), 0);
    EXPECT_EQ(inet::crl::crl_is_revoked_by(nullptr, nullptr, nullptr), -1);

    EXPECT_TRUE(inet::ocsp::ocsp_urls(nullptr).empty());
    EXPECT_EQ(inet::ocsp::ocsp_prepare_request(
                  nullptr, nullptr, nullptr, nullptr, nullptr), 0);
    EXPECT_EQ(inet::ocsp::ocsp_query_responder(
                  nullptr, nullptr, nullptr, nullptr, nullptr, 0), nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_send_request(
                  nullptr, nullptr, nullptr, nullptr, nullptr, 0, 0), nullptr);
    EXPECT_EQ(inet::ocsp::ocsp_send_request(
                  nullptr, reinterpret_cast<OCSP_REQUEST*>(1),
                  const_cast<char*>("host"), const_cast<char*>("/"), nullptr, 1, 0),
              nullptr);
    auto status = inet::ocsp::ocsp_verify_response(nullptr, nullptr, nullptr);
    EXPECT_EQ(status.revoked, -1);
    EXPECT_EQ(status.ttl, 60);
    status = inet::ocsp::ocsp_check_cert(nullptr, nullptr, 0);
    EXPECT_EQ(status.revoked, -1);
    EXPECT_EQ(inet::ocsp::ocsp_check_bytes(nullptr, nullptr), -1);
    ERR_clear_error();
    EXPECT_EQ(inet::ocsp::ocsp_check_bytes("invalid", "invalid"), -1);
    EXPECT_EQ(ERR_peek_error(), 0U);

}

TEST(TLS_Tests, VerifyCallbackMapsCertificateErrorsAndPolicyExceptions) {
    init_log();
    auto certificate = load_tls_test_certificate();
    ASSERT_NE(certificate, nullptr);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ssl_context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ssl_context.get()), SSL_free);
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(
        X509_STORE_new(), X509_STORE_free);
    std::unique_ptr<X509_STORE_CTX, decltype(&X509_STORE_CTX_free)> verify_context(
        X509_STORE_CTX_new(), X509_STORE_CTX_free);
    ASSERT_NE(ssl_context, nullptr);
    ASSERT_NE(ssl, nullptr);
    ASSERT_NE(store, nullptr);
    ASSERT_NE(verify_context, nullptr);
    ASSERT_EQ(X509_STORE_CTX_init(
                  verify_context.get(), store.get(), certificate.get(), nullptr), 1);
    X509_STORE_CTX_set_current_cert(verify_context.get(), certificate.get());
    X509_STORE_CTX_set_error_depth(verify_context.get(), 0);

    SSLCom_Buddy connection;
    ASSERT_EQ(SSL_set_ex_data(ssl.get(), SSLCom::extdata_index(), &connection), 1);
    ASSERT_EQ(X509_STORE_CTX_set_ex_data(
                  verify_context.get(), SSL_get_ex_data_X509_STORE_CTX_idx(), ssl.get()),
              1);
    EXPECT_NE(socle::com::ssl::connection_name(&connection, true).find("<detached>"),
              std::string::npos);

    auto verify = [&](int error, int preverify = 0) {
        X509_STORE_CTX_set_error(verify_context.get(), error);
        return SSLCom::ssl_client_vrfy_callback(preverify, verify_context.get());
    };

    connection.opt.cert.failed_check_replacement = false;
    connection.verify_reset(static_cast<SSLCom::verify_status_t>(
        SSLCom::verify_status_t::VRF_NOTTESTED |
        SSLCom::verify_status_t::VRF_OK));
    EXPECT_EQ(verify(X509_V_OK, 1), 1);
    EXPECT_NE(connection.target_cert(), nullptr);
    EXPECT_EQ(connection.verify_get(), SSLCom::verify_status_t::VRF_OK);

    connection.verify_reset(SSLCom::verify_status_t::VRF_NOTTESTED);
    EXPECT_EQ(verify(X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY), 0);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_UNKNOWN_ISSUER));
    connection.opt.cert.allow_unknown_issuer = true;
    EXPECT_EQ(verify(X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE), 1);

    connection.opt.cert.allow_unknown_issuer = false;
    connection.verify_reset(SSLCom::verify_status_t::VRF_NOTTESTED);
    EXPECT_EQ(verify(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT), 0);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_SELF_SIGNED));
    connection.opt.cert.allow_self_signed = true;
    EXPECT_EQ(verify(X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT), 1);

    connection.opt.cert.allow_self_signed = false;
    connection.verify_reset(SSLCom::verify_status_t::VRF_NOTTESTED);
    EXPECT_EQ(verify(X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN), 0);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_SELF_SIGNED_CHAIN));
    connection.opt.cert.allow_self_signed_chain = true;
    EXPECT_EQ(verify(X509_V_ERR_CERT_UNTRUSTED), 1);

    connection.opt.cert.allow_self_signed_chain = false;
    connection.verify_reset(SSLCom::verify_status_t::VRF_NOTTESTED);
    EXPECT_EQ(verify(X509_V_ERR_CERT_HAS_EXPIRED), 0);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_INVALID));
    connection.opt.cert.allow_not_valid = true;
    EXPECT_EQ(verify(X509_V_ERR_CERT_NOT_YET_VALID), 1);

    connection.opt.cert.allow_not_valid = false;
    connection.verify_reset(SSLCom::verify_status_t::VRF_NOTTESTED);
    EXPECT_EQ(verify(X509_V_ERR_CERT_REVOKED), 0);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_INVALID));

    connection.opt.cert.failed_check_replacement = true;
    EXPECT_EQ(verify(X509_V_ERR_CERT_REVOKED), 1);

    X509_STORE_CTX_set_error_depth(verify_context.get(), 1);
    connection.verify_reset(SSLCom::verify_status_t::VRF_NOTTESTED);
    EXPECT_EQ(verify(X509_V_OK, 1), 1);
    EXPECT_NE(connection.target_issuer(), nullptr);
    X509_STORE_CTX_set_error_depth(verify_context.get(), 2);
    EXPECT_EQ(verify(X509_V_OK, 1), 1);
    EXPECT_NE(connection.target_issuer_issuer(), nullptr);
}

TEST(TLS_Tests, DelayedMitmAcceptGetsAReplacementReadEdge) {
    SSLMitmCom_Buddy downstream;
    EXPECT_FALSE(downstream.forced_read_reset());

    downstream.test_resume_delayed_accept();

    EXPECT_TRUE(downstream.forced_read_reset());
    EXPECT_FALSE(downstream.forced_read_reset());
}

TEST(TLS_Tests, ClientCertificateAndSessionCallbacksRespectPolicyState) {
    init_log();
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context.get()), SSL_free);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(ssl, nullptr);

    SSLCom_Buddy connection;
    ASSERT_EQ(SSL_set_ex_data(ssl.get(), SSLCom::extdata_index(), &connection), 1);
    X509* certificate = reinterpret_cast<X509*>(1);
    EVP_PKEY* key = reinterpret_cast<EVP_PKEY*>(1);

    connection.opt.cert.client_cert_action = 1;
    EXPECT_EQ(SSLCom::ssl_client_cert_callback(
                  ssl.get(), &certificate, &key), 0);
    EXPECT_EQ(certificate, nullptr);
    EXPECT_EQ(key, nullptr);
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_CLIENT_CERT_RQ));

    connection.opt.cert.client_cert_action = 2;
    EXPECT_EQ(SSLCom::ssl_client_cert_callback(
                  ssl.get(), &certificate, &key), 0);
    EXPECT_EQ(certificate, nullptr);
    EXPECT_EQ(key, nullptr);

    connection.opt.cert.client_cert_action = 0;
    connection.opt.cert.failed_check_replacement = false;
    EXPECT_EQ(SSLCom::ssl_client_cert_callback(
                  ssl.get(), &certificate, &key), 0);
    EXPECT_EQ(certificate, nullptr);
    EXPECT_EQ(key, nullptr);

    connection.opt.cert.failed_check_replacement = true;
    EXPECT_EQ(SSLCom::ssl_client_cert_callback(
                  ssl.get(), &certificate, &key), 0);

    connection.opt.cert.client_cert_action = 3;
    EXPECT_EQ(SSLCom::ssl_client_cert_callback(
                  ssl.get(), &certificate, &key), 0);

    std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> session(
        SSL_SESSION_new(), SSL_SESSION_free);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(SSLCom::server_get_session_callback(
                  ssl.get(), nullptr, 0, nullptr), nullptr);
    EXPECT_EQ(SSLCom::new_session_callback(ssl.get(), session.get()), 0);
    connection.verify_bitset(SSLCom::verify_status_t::VRF_REVOKED);
    EXPECT_EQ(SSLCom::new_session_callback(ssl.get(), session.get()), 0);
}

TEST(TLS_Tests, SessionCacheSeparatesEveryVerificationAndCryptoPolicy) {
    SSLComOptions baseline;
    auto const baseline_key = SSLCom::session_policy_fingerprint(baseline);
    EXPECT_FALSE(baseline_key.empty());

    auto expect_partition = [&](auto mutate) {
        auto changed = baseline;
        mutate(changed);
        EXPECT_NE(SSLCom::session_policy_fingerprint(changed), baseline_key);
    };

    expect_partition([](auto& value) { value.bypass = !value.bypass; });
    expect_partition([](auto& value) { value.ct_enable = !value.ct_enable; });
    expect_partition([](auto& value) { value.alpn_block = !value.alpn_block; });
    expect_partition([](auto& value) {
        value.no_fallback_bypass = !value.no_fallback_bypass;
    });
    expect_partition([](auto& value) {
        value.cert.allow_unknown_issuer = !value.cert.allow_unknown_issuer;
    });
    expect_partition([](auto& value) {
        value.cert.allow_self_signed_chain = !value.cert.allow_self_signed_chain;
    });
    expect_partition([](auto& value) {
        value.cert.allow_not_valid = !value.cert.allow_not_valid;
    });
    expect_partition([](auto& value) {
        value.cert.allow_self_signed = !value.cert.allow_self_signed;
    });
    expect_partition([](auto& value) { ++value.cert.client_cert_action; });
    expect_partition([](auto& value) {
        value.ocsp.stapling_enabled = !value.ocsp.stapling_enabled;
    });
    expect_partition([](auto& value) { ++value.ocsp.stapling_mode; });
    expect_partition([](auto& value) { ++value.ocsp.mode; });
    expect_partition([](auto& value) { value.right.kex_dh = !value.right.kex_dh; });
    expect_partition([](auto& value) { value.right.kex_rsa = !value.right.kex_rsa; });
    expect_partition([](auto& value) {
        value.right.allow_sha1 = !value.right.allow_sha1;
    });
    expect_partition([](auto& value) {
        value.right.allow_rc4 = !value.right.allow_rc4;
    });
    expect_partition([](auto& value) {
        value.right.allow_aes128 = !value.right.allow_aes128;
    });

    auto diagnostics_only = baseline;
    ++diagnostics_only.cert.failed_check_override_timeout;
    EXPECT_EQ(SSLCom::session_policy_fingerprint(diagnostics_only), baseline_key);
}

TEST(TLS_Tests, SessionFreshnessCannotOutliveCertificateOrRevocationEvidence) {
    auto key = make_rsa_key();
    auto certificate = make_certificate(key.get(), 4401, "session.example.test");
    std::unique_ptr<SSL_SESSION, decltype(&SSL_SESSION_free)> session(
        SSL_SESSION_new(), SSL_SESSION_free);
    ASSERT_NE(key, nullptr);
    ASSERT_NE(certificate, nullptr);
    ASSERT_NE(session, nullptr);
    ASSERT_EQ(SSL_SESSION_set_timeout(session.get(), 7200), 1);

    SSLComOptions options;
    options.ocsp.mode = 0;
    options.ocsp.stapling_enabled = false;
    auto timeout = session_freshness_timeout(
        session.get(), certificate.get(), options);
    ASSERT_TRUE(timeout.has_value());
    EXPECT_GT(*timeout, 3500UL);
    EXPECT_LE(*timeout, 3600UL);

    const int saved_ocsp_ttl = SSLFactory::options::ocsp_status_ttl;
    const int saved_crl_ttl = SSLFactory::options::crl_status_ttl;
    auto restore_ttls = raw::guard([&] {
        SSLFactory::options::ocsp_status_ttl = saved_ocsp_ttl;
        SSLFactory::options::crl_status_ttl = saved_crl_ttl;
    });
    SSLFactory::options::ocsp_status_ttl = 37;
    SSLFactory::options::crl_status_ttl = 91;
    options.ocsp.mode = 1;
    timeout = session_freshness_timeout(session.get(), certificate.get(), options);
    ASSERT_TRUE(timeout.has_value());
    EXPECT_EQ(*timeout, 37UL);

    ASSERT_NE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), -1), nullptr);
    EXPECT_FALSE(session_freshness_timeout(
        session.get(), certificate.get(), options).has_value());
}

TEST(TLS_Tests, CertificateTransparencyMissingStateFailsClosed) {
    SSLCom_Buddy connection;
    connection.opt.cert.failed_check_replacement = false;
    connection.verify_reset(SSLCom::verify_status_t::VRF_OK);
    EXPECT_EQ(SSLCom::ct_verify_callback(nullptr, nullptr, &connection), 0);
    EXPECT_FALSE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_OK));
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_CT_MISSING));

    connection.opt.cert.failed_check_replacement = true;
    EXPECT_EQ(SSLCom::ct_verify_callback(nullptr, nullptr, &connection), 1);
}

TEST(TLS_Tests, CertificateTransparencyInsufficientValidEntriesFailsClosed) {
    auto* context = CT_POLICY_EVAL_CTX_new();
    ASSERT_NE(context, nullptr);
    auto* scts = sk_SCT_new_null();
    ASSERT_NE(scts, nullptr);
    ASSERT_GT(sk_SCT_push(scts, SCT_new()), 0);
    ASSERT_GT(sk_SCT_push(scts, SCT_new()), 0);

    SSLCom_Buddy connection;
    connection.opt.cert.failed_check_replacement = false;
    connection.verify_reset(SSLCom::verify_status_t::VRF_OK);
    EXPECT_EQ(SSLCom::ct_verify_callback(context, scts, &connection), 0);
    EXPECT_FALSE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_OK));
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_CT_MISSING));
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_CT_FAILED));

    connection.opt.cert.failed_check_replacement = true;
    EXPECT_EQ(SSLCom::ct_verify_callback(context, scts, &connection), 1);

    sk_SCT_pop_free(scts, SCT_free);
    CT_POLICY_EVAL_CTX_free(context);
}

TEST(TLS_Tests, CertificateTransparencyRemainsEnabledWithoutLogList) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
        SSL_new(context.get()), SSL_free);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(ssl, nullptr);

    SSLCom_Buddy connection;
    connection.test_take_ssl(ssl.release());
    connection.opt.ct_enable = true;

    if (SSLFactory::factory().is_ct_available())
        GTEST_SKIP() << "test requires the no-CT-log-list factory state";
    connection.test_init_ssl_callbacks();

    EXPECT_EQ(SSL_ct_is_enabled(connection.test_ssl()), 1);
}

TEST(TLS_Tests, RequestedOcspFailsClosedWithoutTrustStore) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(
        SSL_new(context.get()), SSL_free);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(ssl, nullptr);

    auto& factory = SSLFactory::factory();
    const std::string saved_certs_path = factory.certs_path();
    const std::string saved_password = factory.certs_password();
    const std::string saved_ca_file = factory.ca_file();
    const std::string saved_ca_path = factory.ca_path();
    factory.destroy();
    auto restore_factory = raw::guard([&] {
        factory.destroy();
        factory.certs_path() = saved_certs_path;
        factory.certs_password() = saved_password;
        factory.ca_file() = saved_ca_file;
        factory.ca_path() = saved_ca_path;
        factory.load_from_files();
        factory.load_trust_store();
    });
    SSLCom::factory(&factory);

    SSLCom_Buddy connection;
    connection.test_take_ssl(ssl.release());
    connection.opt.ocsp.stapling_enabled = true;
    connection.opt.ocsp.stapling_mode = 2;
    connection.verify_reset(SSLCom::verify_status_t::VRF_OK);
    connection.test_init_ssl_callbacks();

    EXPECT_EQ(connection.opt.ocsp.stapling_mode, 2);
    EXPECT_TRUE(connection.opt.ocsp.enforce_in_verify);
    EXPECT_FALSE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_OK));
    EXPECT_TRUE(connection.verify_bitcheck(SSLCom::verify_status_t::VRF_ALLFAILED));
    EXPECT_TRUE(connection.error());
}

#ifdef USE_OPENSSL111
TEST(TLS_Tests, CryptoPolicyRestrictsTls13AlongsideLegacyCipherList) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    ASSERT_NE(context, nullptr);

    SSLCom_Buddy no_aes128;
    no_aes128.l4_proto(SOCK_STREAM);
    no_aes128.test_context(context.get());
    no_aes128.opt.ct_enable = false;
    no_aes128.opt.left.allow_aes128 = false;
    no_aes128.test_init_server();
    ASSERT_NE(no_aes128.test_ssl(), nullptr);
    ASSERT_FALSE(no_aes128.error());

    bool tls13_aes128_present = false;
    const auto* ciphers = SSL_get_ciphers(no_aes128.test_ssl());
    for(int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
        const char* name = SSL_CIPHER_get_name(sk_SSL_CIPHER_value(ciphers, i));
        if(name && std::string_view(name).find("TLS_AES_128_") == 0)
            tls13_aes128_present = true;
    }
    EXPECT_FALSE(tls13_aes128_present);

    SSLCom_Buddy no_forward_secrecy;
    no_forward_secrecy.l4_proto(SOCK_STREAM);
    no_forward_secrecy.test_context(context.get());
    no_forward_secrecy.opt.ct_enable = false;
    no_forward_secrecy.opt.left.kex_dh = false;
    no_forward_secrecy.test_init_server();
    ASSERT_NE(no_forward_secrecy.test_ssl(), nullptr);
    ASSERT_FALSE(no_forward_secrecy.error());
    EXPECT_EQ(SSL_get_max_proto_version(no_forward_secrecy.test_ssl()),
              TLS1_2_VERSION);
}
#endif

TEST(TLS_Tests, CompleteClientHelloNormalizationReusesInputBuffer) {
    buffer complete(tls_sni_smithproxy, sizeof(tls_sni_smithproxy));
    SSLCom_Buddy s;
    s.test_peer_hello_buffer(complete);
    const auto* before = s.test_peer_hello_data();

    EXPECT_EQ(s.test_normalize_records(), 1); // client_hello_peek_t::READY
    EXPECT_EQ(s.test_peer_hello_data(), before);
    EXPECT_EQ(s.test_parse_sni(), 1);
    EXPECT_EQ(s.get_sni(), "smithproxy.org");
}




TEST(TLS_Tests, ParseClientHello_SNI) {

    init_log();
    auto& data =  tls_sni_smithproxy;


    buffer b;
    b.assign(data, sizeof(data), sizeof(data), false);

    SSLCom_Buddy s;

    auto log = logan::get();

    log->entry("com.ssl")->level(iDEB);

    s.test_peer_hello_buffer(b);
    s.test_parse_sni();

    std::stringstream ss;

    std::cout << s.hr() << " SNI: " << s.get_sni() << "\n";

    ASSERT_TRUE(s.get_sni() == "smithproxy.org");
}

TEST(TLS_Tests, ParseClientHelloSplitAcrossRecords) {
    constexpr std::size_t header_size = 5;
    const std::size_t payload_size = sizeof(tls_sni_smithproxy) - header_size;

    for (const std::size_t first_payload_size : {1U, 2U, 3U, 4U, 40U}) {
        ASSERT_GT(payload_size, first_payload_size);
        std::vector<unsigned char> split;
        auto add_record = [&](const unsigned char* payload, std::size_t size) {
            split.push_back(0x16);
            split.push_back(0x03);
            split.push_back(0x01);
            split.push_back(static_cast<unsigned char>((size >> 8U) & 0xffU));
            split.push_back(static_cast<unsigned char>(size & 0xffU));
            split.insert(split.end(), payload, payload + size);
        };
        add_record(tls_sni_smithproxy + header_size, first_payload_size);
        add_record(tls_sni_smithproxy + header_size + first_payload_size,
                   payload_size - first_payload_size);

        buffer fragmented(split.data(), split.size());
        SSLCom_Buddy s;
        s.test_peer_hello_buffer(fragmented);

        EXPECT_EQ(s.test_normalize_records(), 1); // client_hello_peek_t::READY
        EXPECT_EQ(s.test_parse_sni(), 1);
        EXPECT_EQ(s.get_sni(), "smithproxy.org");
    }
}

TEST(TLS_Tests, PartialTlsRecordWaitsInsteadOfBecomingBypassCandidate) {
    buffer partial(tls_sni_smithproxy, 17);
    SSLCom_Buddy s;
    s.test_peer_hello_buffer(partial);

    EXPECT_EQ(s.test_normalize_records(), 0); // client_hello_peek_t::WAIT
}

TEST(TLS_Tests, EveryClientHelloPrefixWaitsUntilComplete) {
    for (std::size_t visible = 1; visible < sizeof(tls_sni_smithproxy); ++visible) {
        buffer partial(tls_sni_smithproxy, visible);
        SSLCom_Buddy s;
        s.test_peer_hello_buffer(partial);

        EXPECT_EQ(s.test_normalize_records(), 0) // client_hello_peek_t::WAIT
            << "visible bytes: " << visible;
    }

    buffer complete(tls_sni_smithproxy, sizeof(tls_sni_smithproxy));
    SSLCom_Buddy s;
    s.test_peer_hello_buffer(complete);
    EXPECT_EQ(s.test_normalize_records(), 1); // client_hello_peek_t::READY
}

TEST(TLS_Tests, FragmentedClientHelloPrefixesNeverBecomeBypassCandidates) {
    constexpr std::size_t header_size = 5;
    constexpr std::size_t cut = 4;
    std::vector<unsigned char> fragmented;
    auto add_record = [&](const unsigned char* payload, std::size_t size) {
        fragmented.insert(fragmented.end(), {0x16, 0x03, 0x01,
            static_cast<unsigned char>((size >> 8U) & 0xffU),
            static_cast<unsigned char>(size & 0xffU)});
        fragmented.insert(fragmented.end(), payload, payload + size);
    };
    add_record(tls_sni_smithproxy + header_size, cut);
    add_record(tls_sni_smithproxy + header_size + cut,
               sizeof(tls_sni_smithproxy) - header_size - cut);

    for (std::size_t visible = 1; visible < fragmented.size(); ++visible) {
        buffer partial(fragmented.data(), visible);
        SSLCom_Buddy s;
        s.test_peer_hello_buffer(partial);

        EXPECT_EQ(s.test_normalize_records(), 0) // client_hello_peek_t::WAIT
            << "visible bytes: " << visible;
    }
}

TEST(TLS_Tests, MalformedTlsRecordIsInvalidInsteadOfBypassCandidate) {
    unsigned char malformed[] = {0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00};
    buffer input(malformed, sizeof(malformed));
    SSLCom_Buddy s;
    s.test_peer_hello_buffer(input);

    EXPECT_EQ(s.test_normalize_records(), 3); // client_hello_peek_t::INVALID
}

TEST(TLS_Tests, TruncatedAlertCallbackFailsClosed) {
    SSLCom_Buddy s;
    const unsigned char truncated_alert = 2;

    SSLCom::ssl_msg_callback(0, TLS1_2_VERSION, SSL3_RT_ALERT,
                             &truncated_alert, 1, nullptr, &s);

    EXPECT_TRUE(s.error());
}

TEST(TLS_Tests, AlertCallbackClassifiesSeverityDirectionAndMissingSslState) {
    init_log();
    SSLCom_Buddy s;
    const unsigned char close_notify[] {SSL3_AL_WARNING, SSL_AD_CLOSE_NOTIFY};
    const unsigned char fatal_handshake[] {
        SSL3_AL_FATAL, SSL_AD_HANDSHAKE_FAILURE};

    SSLCom::ssl_msg_callback(0, TLS1_2_VERSION, SSL3_RT_ALERT,
                             close_notify, sizeof(close_notify), nullptr, &s);
    EXPECT_FALSE(s.error());

    // A complete fatal alert must fail closed even if the callback races with
    // SSL teardown and only the owning communication object is still alive.
    SSLCom::ssl_msg_callback(0, TLS1_2_VERSION, SSL3_RT_ALERT,
                             fatal_handshake, sizeof(fatal_handshake), nullptr, &s);
    EXPECT_TRUE(s.error());

    s.error(baseCom::ERROR_NONE);
    SSLCom::ssl_msg_callback(1, TLS1_2_VERSION, SSL3_RT_ALERT,
                             close_notify, sizeof(close_notify), nullptr, &s);
    EXPECT_FALSE(s.error());

    // Sending a fatal alert is terminal for the local TLS state as well.
    SSLCom::ssl_msg_callback(1, TLS1_2_VERSION, SSL3_RT_ALERT,
                             fatal_handshake, sizeof(fatal_handshake), nullptr, &s);
    EXPECT_TRUE(s.error());
}

TEST(TLS_Tests, EmptyHandshakeCallbackIsSafeWithoutConnectionObject) {
    SSLCom::ssl_msg_callback(0, TLS1_2_VERSION, SSL3_RT_HANDSHAKE,
                             nullptr, 0, nullptr, nullptr);
}

TEST(TLS_Tests, DiagnosticCallbacksClassifyEveryRecordAndVersion) {
    init_log();
    SSLCom::log_cb_msg().level(loglevel(iDEB));
    SSLCom::log_cb_info().level(loglevel(iDEB));
    const unsigned char handshake[] {SSL3_MT_CLIENT_HELLO};

    for(int version : {0, SSL2_VERSION, SSL3_VERSION, TLS1_VERSION,
                       TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION, 0x7f7f}) {
        SSLCom::ssl_msg_callback(0, version, SSL3_RT_HANDSHAKE,
                                 handshake, sizeof(handshake), nullptr, nullptr);
    }
    for(int content_type : {SSL3_RT_CHANGE_CIPHER_SPEC, SSL3_RT_HANDSHAKE,
                            SSL3_RT_APPLICATION_DATA, SSL3_RT_HEADER,
                            SSL3_RT_INNER_CONTENT_TYPE, 0x7f7f}) {
        SSLCom::ssl_msg_callback(1, TLS1_2_VERSION, content_type,
                                 handshake, sizeof(handshake), nullptr, nullptr);
    }

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_method()), SSL_CTX_free);
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(context.get()), SSL_free);
    ASSERT_NE(context, nullptr);
    ASSERT_NE(ssl, nullptr);
    SSLCom::ssl_info_callback(ssl.get(), SSL_ST_CONNECT | SSL_CB_LOOP, 1);
    SSLCom::ssl_info_callback(ssl.get(), SSL_ST_ACCEPT | SSL_CB_ALERT | SSL_CB_READ,
                              (SSL3_AL_FATAL << 8) | SSL_AD_HANDSHAKE_FAILURE);
    SSLCom::ssl_info_callback(ssl.get(), SSL_CB_EXIT, 0);
    SSLCom::ssl_info_callback(ssl.get(), SSL_CB_EXIT, -1);

    SSLCom_Buddy connection;
    ERR_raise(ERR_LIB_SSL, SSL_R_BAD_LENGTH);
    EXPECT_EQ(connection.log_if_error(iDEB, "test drain"), 0U);
    EXPECT_EQ(connection.log_if_error(iDEB, "empty drain"), 0U);
}

TEST(TLS_Tests, ParseClientHello_SNI_NoExtensions) {

    init_log();
    auto& data =  tls_teams_50;


    buffer b;
    b.assign(data, sizeof(data), sizeof(data), false);
    SSLCom_Buddy s1, s2;

    auto log = logan::get();
    log->entry("com.ssl")->level(iDEB);

    s1.test_peer_hello_buffer(b);
    ASSERT_THROW(s1.test_parse_sni(), socle::ex::SSL_clienthello_malformed);

    b.size(50);
    s2.test_peer_hello_buffer(b);
    ASSERT_TRUE(s2.test_parse_sni() == 1);

}

TEST(TLS_Tests, ParseClientHello_ALPN) {

    init_log();

    auto& data =  tls_sni_smithproxy_alpn;

    buffer b;
    b.assign(data, sizeof(data), sizeof(data), false);

    SSLCom_Buddy s;

    auto log = logan::get();
    log->entry("com.ssl")->level(iDEB);

    s.test_peer_hello_buffer(b);
    s.test_parse_sni();

    std::stringstream ss;

    std::cout << s.hr() << " SNI: " << s.get_sni() << " ALPN: " << s.get_peer_alpn() << "\n";

    std::stringstream exp;
    exp << static_cast<unsigned char>(0x02);
    exp << "h2";
    exp << static_cast<unsigned char>(0x08);
    exp << "http/1.1";

    ASSERT_TRUE(s.get_peer_alpn() == exp.str());
}

TEST(TLS_Tests, RejectsALPNLengthOutsideExtension) {
    // The ALPN list claims 32767 bytes while its containing extension has two.
    unsigned char data[] = {0x00, 0x10, 0x00, 0x02, 0x7f, 0xff};
    buffer b;
    b.assign(data, sizeof(data), sizeof(data), false);
    SSLCom_Buddy s;

    ASSERT_THROW(s.test_parse_extension(b), socle::ex::SSL_clienthello_malformed);
}

TEST(TLS_Tests, RejectsMalformedALPNProtocolList) {
    const unsigned char empty_protocol[] = {
        0x00, 0x10, 0x00, 0x03, // extension type and payload length
        0x00, 0x01,             // protocol-name list length
        0x00                    // forbidden empty protocol name
    };
    buffer empty_input(empty_protocol, sizeof(empty_protocol));
    SSLCom_Buddy empty_connection;
    EXPECT_THROW(empty_connection.test_parse_extension(empty_input),
                 socle::ex::SSL_clienthello_malformed);

    const unsigned char truncated_protocol[] = {
        0x00, 0x10, 0x00, 0x04, // extension type and payload length
        0x00, 0x02,             // protocol-name list length
        0x03, 'h'               // name length escapes the list
    };
    buffer truncated_input(truncated_protocol, sizeof(truncated_protocol));
    SSLCom_Buddy truncated_connection;
    EXPECT_THROW(truncated_connection.test_parse_extension(truncated_input),
                 socle::ex::SSL_clienthello_malformed);
}

TEST(TLS_Tests, RejectsSNIHostnameOutsideExtension) {
    // A valid SNI envelope cannot contain the claimed 65535-byte hostname.
    unsigned char data[] = {
        0x00, 0x00, 0x00, 0x05, // extension type and payload length
        0x00, 0x03,             // server-name list length
        0x00,                   // host_name
        0xff, 0xff              // impossible hostname length
    };
    buffer b;
    b.assign(data, sizeof(data), sizeof(data), false);
    SSLCom_Buddy s;

    ASSERT_THROW(s.test_parse_extension(b), socle::ex::SSL_clienthello_malformed);
}

TEST(TLS_Tests, RejectsAmbiguousSNIHostNames) {
    const unsigned char embedded_nul[] = {
        0x00, 0x00, 0x00, 0x0b, // extension type and payload length
        0x00, 0x09,             // server-name list length
        0x00, 0x00, 0x06,       // host_name, hostname length
        'a', 0x00, 'b', '.', 'c', 'd'
    };
    buffer nul_input(embedded_nul, sizeof(embedded_nul));
    SSLCom_Buddy nul_connection;
    EXPECT_THROW(nul_connection.test_parse_extension(nul_input),
                 socle::ex::SSL_clienthello_malformed);

    const unsigned char duplicate_host_name[] = {
        0x00, 0x00, 0x00, 0x0e, // extension type and payload length
        0x00, 0x0c,             // server-name list length
        0x00, 0x00, 0x03, 'o', 'n', 'e',
        0x00, 0x00, 0x03, 't', 'w', 'o'
    };
    buffer duplicate_input(duplicate_host_name, sizeof(duplicate_host_name));
    SSLCom_Buddy duplicate_connection;
    EXPECT_THROW(duplicate_connection.test_parse_extension(duplicate_input),
                 socle::ex::SSL_clienthello_malformed);
}
