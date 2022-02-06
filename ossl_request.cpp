#include <stdexcept>

#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <engine.h>

#include "ossl_keyPair.h"
#include "ossl_request.h"

using namespace std;

OsslRequest::OsslRequest(const shared_ptr<OsslKeyPair>& keyPair, const shared_ptr<OsslReqConfig>& config) : keyPair(keyPair)
{
    auto reqConfig = config;

    if (!reqConfig)
        reqConfig = make_shared<OsslReqConfig>();

    if (!keyPair || !*keyPair)
        throw invalid_argument("Key pair not presented");

    pReq = X509_REQ_new();
    if (!pReq)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_REQ_set_version(pReq, reqConfig->version))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    X509_NAME* name = X509_REQ_get_subject_name(pReq);
    if (!name)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    for (auto field : reqConfig->dn)
    {
        if (!X509_NAME_add_entry_by_txt(name, field.first.c_str(), MBSTRING_ASC, reinterpret_cast<const unsigned char*>(field.second.data()), field.second.size(), -1, 0))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    }

    auto exts = sk_X509_EXTENSION_new_null();
    if (!exts)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    for (auto field : reqConfig->exts)
    {
        X509_EXTENSION *ext = X509V3_EXT_conf(NULL, NULL, field.first.c_str(), field.second.c_str());
        if (!ext)
        {
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
        }

        if (!sk_X509_EXTENSION_push(exts, ext))
        {
            sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
        }
    }

    if (!X509_REQ_add_extensions(pReq, exts))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    
    for (auto attr : reqConfig->attrs)
    {
        if (!X509_REQ_add1_attr_by_txt(pReq, attr.first.c_str(), MBSTRING_ASC, reinterpret_cast<const unsigned char*>(attr.second.data()), attr.second.size()))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    }

    if (!X509_REQ_set_pubkey(pReq, *keyPair))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    
    /*int keyNid;
    if (!EVP_PKEY_get_default_digest_nid(*keyPair, &keyNid))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));*/

    if (!X509_REQ_sign(pReq, *keyPair, NULL))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}

OsslRequest::OsslRequest(const vector<uint8_t>& der)
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new_mem_buf(der.data(), der.size()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    pReq = d2i_X509_REQ_bio(memBio.get(), nullptr);
    if (pReq == nullptr)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}

OsslRequest::OsslRequest(const string& filePem)
{
    unique_ptr<FILE, decltype(fclose)*> pemFile(fopen(filePem.c_str(), "rb"), fclose);
    if (!pemFile)
        throw runtime_error("CSR file not found");

    PEM_read_X509_REQ(pemFile.get(), &pReq, NULL, NULL);
    if (pReq == nullptr)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}

vector<uint8_t> OsslRequest::getReqInfo() const
{
    uint8_t* reqInfo = NULL;
    int reqInfoLen = i2d_re_X509_REQ_tbs(pReq, &reqInfo);

    if (!reqInfo)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    vector<uint8_t> ret(reqInfo, reqInfo + reqInfoLen);

    OPENSSL_free(reqInfo);
    
    return ret;
}

OsslRequest::~OsslRequest()
{
    if (pReq)
        X509_REQ_free(pReq);
}

vector<uint8_t> OsslRequest::toDer() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!i2d_X509_REQ_bio(memBio.get(), pReq))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return vector<uint8_t>(reinterpret_cast<uint8_t*>(mem->data), reinterpret_cast<uint8_t*>(mem->data + mem->length));
}

string OsslRequest::toPem() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!PEM_write_bio_X509_REQ(memBio.get(), pReq))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return string(mem->data, mem->length);
}

void OsslRequest::WriteToFile(const string filePem)
{
    unique_ptr<FILE, decltype(fclose)*> pemFile(fopen(filePem.c_str(), "wb"), fclose);
    if (!pemFile)
        throw runtime_error("Fopen for write failed");
        
    if (!PEM_write_X509_REQ(pemFile.get(), pReq))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}