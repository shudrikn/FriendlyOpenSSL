#pragma once

#include <vector>

class RtEngine;

class OsslCipher
{
public:

    enum Algorithm 
    { 
        gost89_CFB_Z, 
        gost89_CBC_Z,
        gost89_CNT_A,
        gost89_CNT_Z,
        gost89_ECB_Z,
        gost89_CTR_A,

        gost3412_2015_M_ECB,
        gost3412_2015_M_CTR,
        gost3412_2015_M_OFB,
        gost3412_2015_M_CBC,
        gost3412_2015_M_CFB,

        gost3412_2015_K_ECB,
        gost3412_2015_K_CTR,
        gost3412_2015_K_OFB,
        gost3412_2015_K_CBC,
        gost3412_2015_K_CFB
    };
    static std::string algToStr(Algorithm alg);
    static Algorithm strToAlg(const std::string& str);
    static int algToNID(Algorithm alg);
    Algorithm nidToAlg(int nid);

    static std::vector<uint8_t> calc(const RtEngine& engine, const std::vector<uint8_t>& key, Algorithm alg, const std::vector<uint8_t>& data, const std::vector<uint8_t>& iv = {});
};