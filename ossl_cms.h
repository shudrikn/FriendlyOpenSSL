#pragma once

#include "ossl_certificate.h"

class OsslCertificate;

typedef struct CMS_ContentInfo_st CMS_ContentInfo;

class OsslCms : public Noncopyable
{
private:
    CMS_ContentInfo* pCms = nullptr;

public:
    OsslCms(const OsslCertificate& cert, const std::vector<uint8_t>& data, bool detached = false);
    ~OsslCms();

    std::vector<uint8_t> toDer() const;
    std::string toPem() const;

    operator CMS_ContentInfo *() const { return pCms; }
};