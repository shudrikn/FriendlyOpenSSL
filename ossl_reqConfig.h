#pragma once

#include <vector>
#include <string>
#include <memory>

struct OsslReqConfig
{
    OsslReqConfig();
    
    long version;
    std::vector<std::pair<std::string, std::string>> dn;
    std::vector<std::pair<std::string, std::string>> attrs;
    std::vector<std::pair<std::string, std::string>> exts;

    static OsslReqConfig dereference(const std::shared_ptr<OsslReqConfig>& ptr)
    {
        if (ptr)
            return *(ptr.get());
        else
            return OsslReqConfig();
    }
};

