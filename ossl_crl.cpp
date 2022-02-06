#include "openssl/x509.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "ossl_crl.h"

using namespace std;

OsslCrl::OsslCrl()
{
    pCrl = X509_CRL_new();
}

OsslCrl::~OsslCrl()
{
    X509_CRL_free(pCrl);
}

vector<uint8_t> OsslCrl::toDer() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!i2d_X509_CRL_bio(memBio.get(), pCrl))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return vector<uint8_t>(reinterpret_cast<uint8_t*>(mem->data), reinterpret_cast<uint8_t*>(mem->data + mem->length));
}

string OsslCrl::toPem() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!PEM_write_bio_X509_CRL(memBio.get(), pCrl))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return string(mem->data, mem->length);
}