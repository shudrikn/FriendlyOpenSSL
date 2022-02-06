#pragma once
#include <time.h>

struct OsslCertConfig
{
    OsslCertConfig()
    {
        startUTCTime = time(NULL);
    }

    long version = 2;
    uint64_t serial = 1;

    time_t startUTCTime;
    uint16_t days = 365 * 2;

    static OsslCertConfig dereference(const std::shared_ptr<OsslCertConfig>& ptr)
    {
        if (ptr)
            return *(ptr.get());
        else
            return OsslCertConfig();
    }
};