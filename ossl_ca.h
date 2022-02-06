#pragma once
#include <memory>
#include <vector>
#include <stdexcept>

#include "ossl_certConfig.h"
#include "ossl_keyPair.h"
#include "ossl_request.h"

class OsslCertificate;
class OsslCrl;

struct OsslRevokeConfig
{
    enum Reason
    {
        unspecified,
        keyCompromise,
        cACompromise,
        affiliationChanged,
        superseded,
        cessationOfOperation,
        certificateHold,
        removeFromCRL,
        privilegeWithdrawn,
        aACompromise
    };

    OsslRevokeConfig() : reason(cessationOfOperation)
    {
        revocationDate = time(NULL);
    }

    time_t revocationDate;
    Reason reason;

    static OsslRevokeConfig dereference(const std::shared_ptr<OsslRevokeConfig>& ptr)
    {
        if (ptr)
            return *(ptr.get());
        else
            return OsslRevokeConfig();
    }
};


struct OsslCrlConfig
{
    OsslCrlConfig()
    {
        thisUpdate = time(NULL);
    }

    long version = 2;
    time_t thisUpdate;
    uint16_t days = 20;

    static OsslCrlConfig dereference(const std::shared_ptr<OsslCrlConfig>& ptr)
    {
        if (ptr)
            return *(ptr.get());
        else
            return OsslCrlConfig();
    }
};

class OsslCa
{
private:
    std::shared_ptr<OsslCertificate> certificate;
    
    uint64_t currentSerial = 0;
    std::vector<std::shared_ptr<OsslCertificate>> issuedCerts;
    std::vector<std::pair<std::shared_ptr<OsslCertificate>, const std::shared_ptr<OsslRevokeConfig>>> revokedCerts;
        
public:
    OsslCa(const std::shared_ptr<OsslCertificate>& certificate);
    ~OsslCa();

    std::shared_ptr<OsslCertificate> signRequest(const std::shared_ptr<OsslRequest>& request, const std::shared_ptr<OsslCertConfig>& certConfig = nullptr);
    std::shared_ptr<OsslCertificate> signRequest(const std::shared_ptr<OsslKeyPair>& keyPair) { return signRequest(std::make_shared<OsslRequest>(keyPair)); };

    void revokeCert(const std::shared_ptr<OsslCertificate>& cert, const std::shared_ptr<OsslRevokeConfig>& config = nullptr);
    
    std::shared_ptr<OsslCrl> getCrl(const std::vector<std::pair<std::shared_ptr<OsslCertificate>, const std::shared_ptr<OsslRevokeConfig>>>& revokedCerts, const std::shared_ptr<OsslCrlConfig>& config = nullptr);
    std::shared_ptr<OsslCrl> getCrl(const std::shared_ptr<OsslCrlConfig>& config = nullptr);
    // создать фейковый crl около заданного размера в КБ
    std::shared_ptr<OsslCrl> getCrl(size_t size);

    std::shared_ptr<OsslCertificate> getCert() { return certificate; }
};