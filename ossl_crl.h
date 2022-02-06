#pragma once
#include <vector>
#include <memory>

#include "ossl_ca.h"
#include "noncopyable.h"

class OsslCrl : public Noncopyable
{
private:
    X509_CRL *pCrl = nullptr;

    OsslCrl();

public:
    
    ~OsslCrl();

    std::vector<uint8_t> toDer() const;
    std::string toPem() const;

    operator X509_CRL*() const { return pCrl; }

    friend std::shared_ptr<OsslCrl> OsslCa::getCrl(const std::vector<std::pair<std::shared_ptr<OsslCertificate>, const std::shared_ptr<OsslRevokeConfig>>>& revoked, const std::shared_ptr<OsslCrlConfig>& config);
};