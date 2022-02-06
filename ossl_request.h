#pragma once
#include <memory>

#include "ossl_reqConfig.h"
#include "noncopyable.h"

class OsslKeyPair;

typedef struct X509_req_st X509_REQ;

class OsslRequest : public Noncopyable
{
private:
    X509_REQ* pReq = nullptr;
    std::shared_ptr<OsslKeyPair> keyPair = nullptr;

public:
    OsslRequest(const std::shared_ptr<OsslKeyPair>& keyPair, const std::shared_ptr<OsslReqConfig>& config = nullptr);
    OsslRequest(const std::vector<uint8_t>& der);
    OsslRequest(const std::string& filePem);
    ~OsslRequest();

    std::shared_ptr<OsslKeyPair> getKeyPair() const { return keyPair; }

    std::vector<uint8_t> getReqInfo() const;

    std::vector<uint8_t> toDer() const;
    std::string toPem() const;

    void WriteToFile(const std::string filePem);

    operator X509_REQ*() { return pReq; }
};