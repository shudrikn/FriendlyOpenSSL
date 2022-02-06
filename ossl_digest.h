#pragma once

#include <string>
#include <vector>

class RtEngine;

class OsslDigest
{
public:
    enum Algorithm { gost94, gost2012_256, gost2012_512 };
    static std::string algToStr(Algorithm alg);
    static Algorithm nidToAlg(int nid);
    static Algorithm oidToAlg(const std::string& oid);
    static Algorithm strToAlg(const std::string& str);
    
    static std::vector<uint8_t> calc(const RtEngine& engine, Algorithm alg, const std::vector<uint8_t>& data);
};

class OsslHmac
{
public:
    // https://tc26.ru/standard/rs/%D0%A0%2050.1.113-2016.pdf
    static std::vector<uint8_t> calc(const RtEngine& engine, const std::vector<uint8_t>& key, OsslDigest::Algorithm alg, const std::vector<uint8_t>& data);
};

class OsslKdf
{
public:
    // https://tc26.ru/standard/rs/%D0%A0%2050.1.113-2016.pdf
    static std::vector<uint8_t> calc(const RtEngine& engine, const std::vector<uint8_t>& key, OsslDigest::Algorithm alg, const std::vector<uint8_t>& label, const std::vector<uint8_t>& seed);
};