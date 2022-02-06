#include <algorithm>

#include <openssl/err.h>
#include <openssl/x509.h>
#include "openssl/txt_db.h"

#include "ossl_ca.h"
#include "ossl_certificate.h"
#include "ossl_crl.h"

using namespace std;

OsslCa::OsslCa(const shared_ptr<OsslCertificate>& certificate) : certificate(certificate)
{
    if (!certificate->getKeyPair())
        throw invalid_argument("Create CA allowed only for certs with key pair");
}

OsslCa::~OsslCa()
{
    
}

shared_ptr<OsslCertificate> OsslCa::signRequest(const shared_ptr<OsslRequest>& request, const shared_ptr<OsslCertConfig>& certConfig)
{
    auto caCertConfig = certConfig;
    if (!caCertConfig)
        caCertConfig = make_shared<OsslCertConfig>();

    caCertConfig->serial = currentSerial;
    ++currentSerial;
    
    auto newCert = make_shared<OsslCertificate>(certificate, request, caCertConfig);
    issuedCerts.push_back(newCert);
    
    return newCert;
}


void OsslCa::revokeCert(const shared_ptr<OsslCertificate>& cert, const shared_ptr<OsslRevokeConfig>& config)
{
    auto certIt = find(issuedCerts.begin(), issuedCerts.end(), cert);
    if (certIt == issuedCerts.end())
        throw runtime_error("Certificate doesn't exist or has been revoked");
    
    revokedCerts.push_back(make_pair(*certIt, config));
    issuedCerts.erase(certIt);
}

shared_ptr<OsslCrl> OsslCa::getCrl(const vector<pair<shared_ptr<OsslCertificate>, const shared_ptr<OsslRevokeConfig>>>& revoked, const shared_ptr<OsslCrlConfig>& crlConfig)
{
    auto crlConf = OsslCrlConfig::dereference(crlConfig);

    auto ptr = new OsslCrl();
    auto crl = shared_ptr<OsslCrl>(ptr);

    if (!X509_CRL_set_issuer_name(*crl, X509_get_subject_name(*certificate)))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));


    unique_ptr<ASN1_TIME, decltype(ASN1_STRING_free)*> lastUpdate(ASN1_TIME_adj(NULL, crlConf.thisUpdate, 0, 0), ASN1_STRING_free);
    if (!lastUpdate)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_CRL_set1_lastUpdate(*crl, lastUpdate.get()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<ASN1_TIME, decltype(ASN1_STRING_free)*> nextUpdate(ASN1_TIME_adj(NULL, crlConf.thisUpdate, crlConf.days, 0), ASN1_STRING_free);
    if (!nextUpdate)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_CRL_set1_nextUpdate(*crl, nextUpdate.get()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));


    for (auto revokedCert : revoked)
    {
        auto revokedCertSecond = OsslRevokeConfig::dereference(revokedCert.second);

        X509_REVOKED *revoked = X509_REVOKED_new();
        if (!revoked)
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

        //revaked date
        unique_ptr<ASN1_TIME, decltype(ASN1_TIME_free)*> time(ASN1_TIME_new(), ASN1_TIME_free);
        if (!time)
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

        auto revocationDate = revokedCertSecond.revocationDate;
        if (!X509_time_adj(time.get(), 0, &revocationDate))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

        if (!X509_REVOKED_set_revocationDate(revoked, time.get()))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

        //reason
        unique_ptr<ASN1_ENUMERATED, decltype(ASN1_ENUMERATED_free)*> reason(ASN1_ENUMERATED_new(), ASN1_ENUMERATED_free);
        if (!reason)
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

        auto reasonConf = revokedCertSecond.reason;
        if (!ASN1_ENUMERATED_set(reason.get(), reasonConf))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

        if (!X509_REVOKED_add1_ext_i2d(revoked, NID_crl_reason, reason.get(), 0, 0))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

        //serial
        unique_ptr<ASN1_INTEGER, decltype(ASN1_INTEGER_free)*> serial(ASN1_TIME_new(), ASN1_INTEGER_free);
        if (!serial)
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

        if (revokedCert.first)
        {
            if (!ASN1_INTEGER_set(serial.get(), revokedCert.first->getSerial()))
                throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
        }
        else
        {
            long fakeSerial = 0x1;
            if (!ASN1_INTEGER_set(serial.get(), fakeSerial))
                throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
        }

        if (!X509_REVOKED_set_serialNumber(revoked, serial.get()))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));


        if (!X509_CRL_add0_revoked(*crl, revoked))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    }

    if (!X509_CRL_sort(*crl))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_CRL_set_version(*crl, crlConf.version))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!X509_CRL_sign(*crl, *(certificate->getKeyPair()), NULL))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return crl;
}

shared_ptr<OsslCrl> OsslCa::getCrl(const shared_ptr<OsslCrlConfig>& crlConfig)
{
    return getCrl(revokedCerts, crlConfig);
}


shared_ptr<OsslCrl> OsslCa::getCrl(size_t size)
{
    size *= 1024;

    vector<pair<shared_ptr<OsslCertificate>, const shared_ptr<OsslRevokeConfig>>> revoked;
    
    shared_ptr<OsslCrl> crl;

    size_t crlSize = 0;
    crl = getCrl(revoked);
    crlSize = crl->toDer().size();

    revoked.resize((size - crlSize) / 34); //35 - примерный размер одного отозванного сертификата в CRL

    do
    {
        crl = getCrl(revoked);
        crlSize = crl->toDer().size();
        revoked.resize(revoked.size() + 1);
    } while (crlSize < size);

    return crl;
}