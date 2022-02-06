#include "openssl/cms.h"
#include <openssl/err.h>
#include <openssl/pem.h>

#include "ossl_certificate.h"
#include "ossl_cms.h"

using namespace std;

OsslCms::OsslCms(const OsslCertificate& cert, const vector<uint8_t>& data, bool detached)
{
    if (!cert.getKeyPair())
        throw invalid_argument("CMS sign allowed only for certs with key pair");

    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new_mem_buf(data.data(), data.size()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    int flags = CMS_BINARY | CMS_NOSMIMECAP | (detached ? CMS_DETACHED : 0);

    pCms = CMS_sign(cert, *(cert.getKeyPair()), NULL, memBio.get(), flags);
    if (!pCms)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

}

OsslCms::~OsslCms()
{
    CMS_ContentInfo_free(pCms);
}

vector<uint8_t> OsslCms::toDer() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!i2d_CMS_bio(memBio.get(), pCms))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return vector<uint8_t>(reinterpret_cast<uint8_t*>(mem->data), reinterpret_cast<uint8_t*>(mem->data + mem->length));
}

string OsslCms::toPem() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!PEM_write_bio_CMS_stream(memBio.get(), pCms, NULL, 0))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return string(mem->data, mem->length);
}