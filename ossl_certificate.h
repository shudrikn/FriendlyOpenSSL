#pragma once

#include <vector>
#include <string>
#include <memory>

#include "ossl_reqConfig.h"
#include "ossl_certConfig.h"
#include "ossl_keyPair.h"

class OsslRequest;

typedef struct x509_st X509;

class OsslCertificate : public Noncopyable
{
private:
    X509 *pCertificate = nullptr;
    std::shared_ptr<OsslKeyPair> keyPair = nullptr;

public:
    //imported
    OsslCertificate(const std::vector<uint8_t>& der, const std::shared_ptr<OsslKeyPair>& keyPair = nullptr);
    OsslCertificate(const std::string& pem, const std::shared_ptr<OsslKeyPair>& keyPair = nullptr);
    //self-signed
    OsslCertificate(const std::shared_ptr<OsslKeyPair>& keyPair, const std::shared_ptr<OsslReqConfig>& reqConfig = nullptr, const std::shared_ptr<OsslCertConfig>& config = nullptr);
    //CA
    OsslCertificate(const std::shared_ptr<OsslCertificate>& signerCert, const std::shared_ptr<OsslRequest>& request, const std::shared_ptr<OsslCertConfig>& config = nullptr);
    OsslCertificate(const std::shared_ptr<OsslCertificate>& signerCert, const std::shared_ptr<OsslKeyPair>& keyPair) : OsslCertificate(signerCert, std::make_shared<OsslRequest>(keyPair)) {};
    ~OsslCertificate();

    std::shared_ptr<OsslKeyPair> getKeyPair() const { return keyPair; }

    long getSerial();

    std::vector<uint8_t> toDer() const;
    std::string toPem() const;

    operator X509*() const { return pCertificate; }
};