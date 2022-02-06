#include <memory>

#include <openssl/bio.h>
#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "ossl_cipher.h"
#include "rtengine.h"

using namespace std;

string OsslCipher::algToStr(Algorithm alg)
{
    string result;
        
    if (alg == gost89_CFB_Z)
        result = "gost89";
    else if (alg == gost89_CBC_Z)
        result = "gost89-cbc";
    else if (alg == gost89_CNT_A)
        result = "gost89-cnt";
    else if (alg == gost89_CNT_Z)
        result = "gost89-cnt-12";
    else if (alg == gost89_ECB_Z)
        result = "gost89-ecb"; 
    else if (alg == gost89_CTR_A)
        result = "gost89-ctr";
    else if (alg == gost3412_2015_M_ECB)
        result = "magma-ecb"; 
    else if (alg == gost3412_2015_M_CTR)
        result = "magma-ctr"; 
    else if (alg == gost3412_2015_M_OFB)
        result = "magma-ofb"; 
    else if (alg == gost3412_2015_M_CBC)
        result = "magma-cbc"; 
    else if (alg == gost3412_2015_M_CFB)
        result = "magma-cfb"; 
    else if (alg == gost3412_2015_K_ECB)
        result = "grasshopper-ecb"; 
    else if (alg == gost3412_2015_K_CTR)
        result = "grasshopper-ctr"; 
    else if (alg == gost3412_2015_K_OFB)
        result = "grasshopper-ofb"; 
    else if (alg == gost3412_2015_K_CBC)
        result = "grasshopper-cbc"; 
    else if (alg == gost3412_2015_K_CFB)
        result = "grasshopper-cfb";
    else
        throw invalid_argument("Unknown cipher algorithm");

    return result;
}

OsslCipher::Algorithm OsslCipher::strToAlg(const string& str)
{
    Algorithm result;

    if (str == "gost89")
        result = gost89_CFB_Z;
    else if (str == "gost89-cbc")
        result = gost89_CBC_Z;
    else if (str == "gost89-cnt")
        result = gost89_CNT_A;
    else if (str == "gost89-cnt-12")
        result = gost89_CNT_Z;
    else if (str == "gost89-ecb")
        result = gost89_ECB_Z;
    else if (str == "gost89-ctr")
        result = gost89_CTR_A;
    else if (str == "magma-ecb")
        result = gost3412_2015_M_ECB;
    else if (str == "magma-ctr")
        result = gost3412_2015_M_CTR;
    else if (str == "magma-ofb")
        result = gost3412_2015_M_OFB;
    else if (str == "magma-cbc")
        result = gost3412_2015_M_CBC;
    else if (str == "magma-cfb")
        result = gost3412_2015_M_CFB;
    else if (str == "grasshopper-ecb")
        result = gost3412_2015_K_ECB;
    else if (str == "grasshopper-ctr")
        result = gost3412_2015_K_CTR;
    else if (str == "grasshopper-ofb")
        result = gost3412_2015_K_OFB;
    else if (str == "grasshopper-cbc")
        result = gost3412_2015_K_CBC;
    else if (str == "grasshopper-cfb")
        result = gost3412_2015_K_CFB;
    else
        throw invalid_argument("Unknown cipher algorithm");

    return result;
}

OsslCipher::Algorithm OsslCipher::nidToAlg(int nid)
{
    const char * str = OBJ_nid2sn(nid);
    if (!str)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return strToAlg(str);
}

int OsslCipher::algToNID(Algorithm alg)
{
    string str = algToStr(alg);

    int nid = OBJ_sn2nid(str.c_str());
    if (nid == NID_undef)
        throw invalid_argument("Unknown NID");

    return nid;
}

vector<uint8_t> OsslCipher::calc(const RtEngine& engine, const vector<uint8_t>& key, Algorithm alg, const vector<uint8_t>& data, const vector<uint8_t>& iv)
{
    int outlen, tmplen;
    vector<uint8_t> result(data.size() + 100);

    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algToStr(alg).c_str());
    if (!cipher)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<EVP_CIPHER_CTX, decltype(EVP_CIPHER_CTX_free)*> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_EncryptInit_ex(ctx.get(), cipher, engine, key.data(), iv.data()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_EncryptUpdate(ctx.get(), result.data(), &outlen, data.data(), data.size()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_EncryptFinal_ex(ctx.get(), result.data() + outlen, &tmplen))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    result.resize(outlen + tmplen);
    
    return result;
}