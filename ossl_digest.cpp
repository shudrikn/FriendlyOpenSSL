#include <memory>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

#include "ossl_digest.h"
#include "rtengine.h"

using namespace std;

string OsslDigest::algToStr(Algorithm alg)
{
    string result;
    switch (alg)
    {
    case gost94:
        result = "md_gost94";
        break;
    case gost2012_256:
        result = "md_gost12_256";
        break;
    case gost2012_512:
        result = "md_gost12_512";
        break;
    default:
        throw invalid_argument("Incorrect digest algorithm");
        break;
    }
    return result;
}

OsslDigest::Algorithm OsslDigest::oidToAlg(const string& oid)
{
    Algorithm result;
   
    if (oid == "1.2.643.2.2.9")
        result = gost94;
    else if (oid == "1.2.643.7.1.1.2.2")
        result = gost2012_256;
    else if (oid == "1.2.643.7.1.1.2.3")
        result = gost2012_512;
    else
        throw invalid_argument("Unknown digest algorithm");
    
    return result;
}

OsslDigest::Algorithm OsslDigest::strToAlg(const string& str)
{
    Algorithm result;

    if (str == "md_gost94")
        result = gost94;
    else if (str == "md_gost12_256")
        result = gost2012_256;
    else if (str == "md_gost12_512")
        result = gost2012_512;
    else
        throw invalid_argument("Unknown digest algorithm");

    return result;
}

OsslDigest::Algorithm OsslDigest::nidToAlg(int nid)
{
    const char * str = OBJ_nid2sn(nid);
    if (!str)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return strToAlg(str);
}

vector<uint8_t> OsslDigest::calc(const RtEngine& engine, Algorithm alg, const vector<uint8_t>& data)
{
    const EVP_MD *md = EVP_get_digestbyname(algToStr(alg).c_str());
    if (!md)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<EVP_MD_CTX, decltype(EVP_MD_CTX_free)*> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_DigestInit_ex(ctx.get(), md, engine))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_DigestUpdate(ctx.get(), data.data(), data.size()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    vector<uint8_t> result;
    result.resize(EVP_MAX_MD_SIZE);
    unsigned int md_len;

    if (!EVP_DigestFinal_ex(ctx.get(), result.data(), &md_len))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    result.resize(md_len);

    return result;
}

vector<uint8_t> OsslHmac::calc(const RtEngine& engine, const vector<uint8_t>& key, OsslDigest::Algorithm alg, const vector<uint8_t>& data)
{
    unsigned int outlen;
    vector<uint8_t> result(EVP_MAX_MD_SIZE);

    const EVP_MD *md = EVP_get_digestbyname(OsslDigest::algToStr(alg).c_str());
    if (!md)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<HMAC_CTX, decltype(HMAC_CTX_free)*> ctx(HMAC_CTX_new(), HMAC_CTX_free);
    if (!ctx)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!HMAC_Init_ex(ctx.get(), key.data(), key.size(), md, engine))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!HMAC_Update(ctx.get(), data.data(), data.size()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!HMAC_Final(ctx.get(), result.data(), &outlen))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    result.resize(outlen);

    return result;
}

vector<uint8_t> OsslKdf::calc(const RtEngine& engine, const vector<uint8_t>& key, OsslDigest::Algorithm alg, const vector<uint8_t>& label, const vector<uint8_t>& seed)
{
    vector<uint8_t> vectorForKdf = {0x01};
    vectorForKdf.insert(vectorForKdf.end(), label.begin(), label.end());
    vectorForKdf.push_back(0x00);
    vectorForKdf.insert(vectorForKdf.end(), seed.begin(), seed.end());
    vectorForKdf.push_back(0x01);
    vectorForKdf.push_back(0x00);
    return OsslHmac::calc(engine, key, alg, vectorForKdf);
}