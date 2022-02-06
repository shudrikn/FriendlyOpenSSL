#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "ossl_keyPair.h"
#include "ossl_certificate.h"
#include "ossl_reqConfig.h"
#include "ossl_digest.h"
#include "ossl_request.h"

using namespace std;

OsslCertificate::OsslCertificate(const vector<uint8_t>& der, const shared_ptr<OsslKeyPair>& keyPair) : keyPair(keyPair)
{
    pCertificate = X509_new();
    if (!pCertificate)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    auto data = der.data();
    if (!d2i_X509(&pCertificate, &data, der.size()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}

OsslCertificate::OsslCertificate(const string& pem, const shared_ptr<OsslKeyPair>& keyPair) : keyPair(keyPair)
{
    pCertificate = X509_new();
    if (!pCertificate)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new_mem_buf(pem.data(), pem.size()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    pCertificate = PEM_read_bio_X509(memBio.get(), NULL, NULL, NULL);
    if (!pCertificate)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}

OsslCertificate::OsslCertificate(const shared_ptr<OsslKeyPair>& keyPair, const shared_ptr<OsslReqConfig>& reqConfig, const shared_ptr<OsslCertConfig>& certConfig) : keyPair(keyPair)
{
    if (!keyPair || !*keyPair)
        throw invalid_argument("Key pair not presented");

    OsslReqConfig reqConf = OsslReqConfig::dereference(reqConfig);
    OsslCertConfig certConf = OsslCertConfig::dereference(certConfig);
  
    pCertificate = X509_new();
    if (!pCertificate)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
        
    if (!X509_set_version(pCertificate, certConf.version))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
        
    auto serial = X509_get_serialNumber(pCertificate);
    if (!serial)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!ASN1_INTEGER_set_uint64(serial, certConf.serial))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    auto notBefore = X509_get_notBefore(pCertificate);
    if (!notBefore)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_time_adj(notBefore, 0, const_cast<time_t*>(&certConf.startUTCTime)))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    
    auto notAfter = X509_get_notAfter(pCertificate);
    if (!notAfter)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_time_adj_ex(notAfter, certConf.days, 0, const_cast<time_t*>(&certConf.startUTCTime)))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_set_pubkey(pCertificate, *keyPair))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    X509_NAME* name = X509_get_subject_name(pCertificate);
    if (!name)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    for (auto field : reqConf.dn)
    {
        if (!X509_NAME_add_entry_by_txt(name, field.first.c_str(), MBSTRING_ASC, reinterpret_cast<const unsigned char*>(field.second.data()), field.second.size(), -1, 0))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    }

    if (!X509_set_issuer_name(pCertificate, name))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
        
    for (auto field : reqConf.exts)
    {
        auto ext = X509V3_EXT_conf(NULL, NULL, field.first.c_str(), field.second.c_str());
        if (!ext)
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

        if (!X509_add_ext(pCertificate, ext, -1))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    }

    /*int keyNid;
    if (!EVP_PKEY_get_default_digest_nid(*keyPair, &keyNid))
    throw runtime_error(ERR_error_string(ERR_get_error(), NULL));*/

    if (!X509_sign(pCertificate, *keyPair, NULL))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

}

OsslCertificate::OsslCertificate(const shared_ptr<OsslCertificate>& signerCert, const shared_ptr<OsslRequest>& request, const shared_ptr<OsslCertConfig>& certConfig) : keyPair(request->getKeyPair())
{
    if (!signerCert->getKeyPair())
        throw invalid_argument("Sign request allowed only for certs with key pair");

    OsslCertConfig certConf = OsslCertConfig::dereference(certConfig);

    pCertificate = X509_new();
    if (!pCertificate)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_set_version(pCertificate, certConf.version))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<STACK_OF(X509_EXTENSION), void(*)(STACK_OF(X509_EXTENSION)*)> ex(X509_REQ_get_extensions(*request),
        [](STACK_OF(X509_EXTENSION)* p) {
        sk_X509_EXTENSION_pop_free(p, X509_EXTENSION_free);
    });

    for (int i = 0; ex && i < sk_X509_EXTENSION_num(ex.get()); ++i)
        if (!X509_add_ext(pCertificate, sk_X509_EXTENSION_value(ex.get(), i), -1))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    X509_NAME* subject = X509_get_subject_name(pCertificate);
    X509_NAME* csrSubj = X509_REQ_get_subject_name(*request);

    for (int i = 0; i < X509_NAME_entry_count(csrSubj); ++i)
        if (!X509_NAME_add_entry(subject, X509_NAME_get_entry(csrSubj, i), -1, 0))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_set_pubkey(pCertificate, X509_REQ_get0_pubkey(*request)))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_set_issuer_name(pCertificate, X509_get_subject_name(*signerCert)))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    auto serial = X509_get_serialNumber(pCertificate);
    if (!serial)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!ASN1_INTEGER_set_uint64(serial, certConf.serial))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    auto notBefore = X509_get_notBefore(pCertificate);
    if (!notBefore)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_time_adj(notBefore, 0, const_cast<time_t*>(&certConf.startUTCTime)))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    auto notAfter = X509_get_notAfter(pCertificate);
    if (!notAfter)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_time_adj_ex(notAfter, certConf.days, 0, const_cast<time_t*>(&certConf.startUTCTime)))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    /*int keyNid;
    if (!EVP_PKEY_get_default_digest_nid(*keyPair, &keyNid))
    throw runtime_error(ERR_error_string(ERR_get_error(), NULL));*/

    if (!X509_sign(pCertificate, *(signerCert->getKeyPair()), NULL))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));   
}

OsslCertificate::~OsslCertificate()
{
    if (pCertificate)
        X509_free(pCertificate);
}

long OsslCertificate::getSerial()
{
    auto serial = X509_get_serialNumber(pCertificate);
    if (!serial)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return ASN1_INTEGER_get(serial);
}

vector<uint8_t> OsslCertificate::toDer() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!i2d_X509_bio(memBio.get(), pCertificate))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return vector<uint8_t>(reinterpret_cast<uint8_t*>(mem->data), reinterpret_cast<uint8_t*>(mem->data + mem->length));
}

string OsslCertificate::toPem() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!PEM_write_bio_X509(memBio.get(), pCertificate))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return string(mem->data, mem->length);
}
