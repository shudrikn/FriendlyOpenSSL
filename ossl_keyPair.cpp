#include <memory>
#include <stdexcept>

#include <openssl/ossl_typ.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <engine.h>

#include "rtengine.h"
#include "ossl_keyPair.h"
#include "ossl_reqConfig.h"

using namespace std;

string OsslKeyPair::typeToStr(Type type)
{
    string result;

    switch (type)
    {
    case gost2001:
        result = "gost2001";
        break;
    case gost2012_256:
        result = "gost2012_256";
        break;
    case gost2012_512:
        result = "gost2012_512";
        break;
    default:
        throw invalid_argument("Incorrect key pair type");
        break;
    }
    return result;
}



OsslKeyPair::Type OsslKeyPair::strToType(const string& str)
{
    Type result;

    if (str == "gost2001")
        result = gost2001;
    else if (str == "gost2012_256")
        result = gost2012_256;
    else if (str == "gost2012_512")
        result = gost2012_512;
    else
        throw invalid_argument("Unknown key type");

    return result;
}

OsslKeyPair::OsslKeyPair(const string& file, FileType fileType)
{
    unique_ptr<FILE, decltype(fclose)*> pemFile(fopen(file.c_str(), "rb"), fclose);
    if (!pemFile)
        throw runtime_error("File not found");

    if (fileType == privateKeyPem)
        pKey = PEM_read_PrivateKey(pemFile.get(), NULL, 0, NULL);
    else if (fileType == publicKeyPem)
        pKey = PEM_read_PUBKEY(pemFile.get(), NULL, 0, NULL);
    else
        throw runtime_error("Unknown file type");

    if (pKey == NULL)
    {
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    }
}

OsslKeyPair::~OsslKeyPair()
{
    if (pKey)
        EVP_PKEY_free(pKey);
}

string OsslGostKeyPair::paramsetToStr(Type type, Paramset paramset)
{
    string result;
    // https://jira.aktivco.ru/browse/NANO-812
    if (type == gost2001)
    {
        switch (paramset)
        {
        case A:
            result = "A";
            break;
        case B:
            result = "B";
            break;
        case C:
            result = "C";
            break;
        default:
            throw invalid_argument("Unknown key pair paramset");
            break;
        }
    }
    else if (type == gost2012_256)
    {
        switch (paramset)
        {
        case A:
            result = "id-GostR3410-2001-CryptoPro-A-ParamSet";
            break;
        case B:
            result = "id-GostR3410-2001-CryptoPro-B-ParamSet";
            break;
        case C:
            result = "id-GostR3410-2001-CryptoPro-C-ParamSet";
            break;
        case TCA:
            result = "A";
            break;
        case TCB:
            result = "B";
            break;
        case TCC:
            result = "C";
            break;
        case TCD:
            result = "D";
            break;
        default:
            throw invalid_argument("Unknown key pair paramset");
            break;
        }
    }
    else if (type == gost2012_512)
    {
        switch (paramset)
        {
        case A:
            result = "A";
            break;
        case B:
            result = "B";
            break;
        case C:
            result = "C";
            break;
        default:
            throw invalid_argument("Unknown key pair paramset");
            break;
        }
    }
    else
    {
        throw invalid_argument("Unknown key pair type");
    }

    return result;
}

int OsslGostKeyPair::paramsetToNid(Type type, Paramset paramset)
{
    int result = 0;

    switch (paramset)
    {
    case A:
        if (type == gost2001 || type == gost2012_256)
            result = NID_id_GostR3410_2001_CryptoPro_A_ParamSet;
        else if (type == gost2012_512)
            result = NID_id_tc26_gost_3410_2012_512_paramSetA;
        else
            throw invalid_argument("Incorrect key pair paramset");
        break;
    case B:
        if (type == gost2001 || type == gost2012_256)
            result = NID_id_GostR3410_2001_CryptoPro_B_ParamSet;
        else if (type == gost2012_512)
            result = NID_id_tc26_gost_3410_2012_512_paramSetB;
        else
            throw invalid_argument("Incorrect key pair paramset");
        break;
    case C:
        if (type == gost2001 || type == gost2012_256)
            result = NID_id_GostR3410_2001_CryptoPro_C_ParamSet;
        else
            throw invalid_argument("Incorrect key pair paramset");
        break;
    default:
        throw invalid_argument("Incorrect key pair paramset");
    }

    return result;
}

OsslGostKeyPair::Paramset OsslGostKeyPair::strToParamset(const string& str)
{
    Paramset result;

    if (str == "A")
        result = A;
    else if (str == "B")
        result = B;
    else if (str == "C")
        result = C;
    else
        throw invalid_argument("Unknown key paramset");

    return result;
}

OsslGostKeyPair::OsslGostKeyPair(const RtEngine& engine, Type type, Paramset paramset) : OsslKeyPair(type), paramset(paramset)
{
    unique_ptr<EVP_PKEY, decltype(EVP_PKEY_free)*> tempKey(EVP_PKEY_new(), EVP_PKEY_free);
    if (!tempKey)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    
    auto typeStr = typeToStr(type);
    if (!EVP_PKEY_set_type_str(tempKey.get(), typeStr.c_str(), typeStr.size()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<EVP_PKEY_CTX, decltype(EVP_PKEY_CTX_free)*> ctx(EVP_PKEY_CTX_new(tempKey.get(), engine), EVP_PKEY_CTX_free);
    if (!ctx)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_PKEY_keygen_init(ctx.get()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    
    auto paramsetStr = paramsetToStr(type, paramset);
    if (!EVP_PKEY_CTX_ctrl_str(ctx.get(), "paramset", paramsetStr.c_str()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_PKEY_keygen(ctx.get(), &pKey))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}

vector<uint8_t> OsslKeyPair::rawSign(const vector<uint8_t>& data) const
{
    vector<uint8_t> result;
    size_t size;

    unique_ptr<EVP_MD_CTX, decltype(EVP_MD_CTX_free)*> signCtx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
    if (!signCtx)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_DigestSignInit(signCtx.get(), NULL, NULL, NULL, pKey))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    
    if (!EVP_DigestSignUpdate(signCtx.get(), data.data(), data.size()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    
    if (!EVP_DigestSignFinal(signCtx.get(), NULL, &size))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    result.resize(size);
    
    if (!EVP_DigestSignFinal(signCtx.get(), result.data(), &size))
       throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    result.resize(size);
    
    return result;
}

bool OsslKeyPair::verify(EVP_PKEY* pKey, const vector<uint8_t>& data, const vector<uint8_t>& sign, const shared_ptr<OsslDigest::Algorithm>& digestAlg, const shared_ptr<RtEngine>& engine)
{
    const EVP_MD *md;
    if (digestAlg)
    {
        md = EVP_get_digestbyname(OsslDigest::algToStr(*digestAlg).c_str());
        if (!md)
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    }
    else
        md = NULL;

    int keyNid;
    if (!EVP_PKEY_get_default_digest_nid(pKey, &keyNid))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<EVP_MD_CTX, decltype(EVP_MD_CTX_free)*> verifyCtx(EVP_MD_CTX_create(), EVP_MD_CTX_free);
    if (!verifyCtx)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (engine)
    {
        if (!EVP_DigestVerifyInit(verifyCtx.get(), NULL, md, *engine, pKey))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    }
    else
    {
        if (!EVP_DigestVerifyInit(verifyCtx.get(), NULL, md, NULL, pKey))
            throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    }

    if (!EVP_DigestVerifyUpdate(verifyCtx.get(), data.data(), data.size()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_DigestVerifyFinal(verifyCtx.get(), sign.data(), sign.size()))
        return false;

    return true;
}

bool OsslKeyPair::verify(const vector<uint8_t>& data, const vector<uint8_t>& sign, const shared_ptr<OsslDigest::Algorithm>& digestAlg) const
{
    return verify(pKey, data, sign, digestAlg);
}

bool OsslGostKeyPair::verify(const RtEngine& engine, const vector<uint8_t>& pubKeyValue, Type keyType, Paramset keyParamset, const vector<uint8_t>& data, const vector<uint8_t>& sign, const shared_ptr<OsslDigest::Algorithm>& digestAlg)
{
    OsslGostKeyPair tempKey(engine, keyType, keyParamset);

    if (!EVP_PKEY_set1_engine(tempKey, engine))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    EC_KEY* ecKey = reinterpret_cast<EC_KEY*>(EVP_PKEY_get0(tempKey));
    if (!ecKey)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    
    const EC_GROUP* ecGroup = EC_KEY_get0_group(ecKey);
    if (!ecGroup)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<BIGNUM, decltype(BN_free)*> bignumY(BN_bin2bn(pubKeyValue.data(), pubKeyValue.size() / 2, NULL), BN_free);
    if (!bignumY)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<BIGNUM, decltype(BN_free)*> bignumX(BN_bin2bn(pubKeyValue.data() + pubKeyValue.size() / 2, pubKeyValue.size() / 2, NULL), BN_free);
    if (!bignumX)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    unique_ptr<EC_POINT, decltype(EC_POINT_free)*> ecPoint(EC_POINT_new(ecGroup), EC_POINT_free);
    if (!ecPoint)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EC_POINT_set_affine_coordinates_GFp(ecGroup, ecPoint.get(), bignumX.get(), bignumY.get(), NULL))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EC_KEY_set_public_key(ecKey, ecPoint.get()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    bool result = OsslKeyPair::verify(tempKey, data, sign, digestAlg);
       
    return result;
}

vector<uint8_t> OsslGostKeyPair::ecdh(const RtEngine& engine, const vector<uint8_t>& publicKey) const
{
	// импорт публичного ключа токена в Openssl
	OsslGostKeyPair pairTemp(engine, getType(), getParamset());

	unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
	if (!memBio)
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	if (!i2d_PUBKEY_bio(memBio.get(), pairTemp))
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	BUF_MEM *mem = NULL;
	BIO_get_mem_ptr(memBio.get(), &mem);
	if (!mem)
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	memcpy(mem->data + mem->length - publicKey.size(), publicKey.data(), publicKey.size());

	if (!d2i_PUBKEY_bio(memBio.get(), pairTemp))
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	const EC_KEY* ecKeyPeer = reinterpret_cast<const EC_KEY*>(EVP_PKEY_get0(pairTemp));
	if (!ecKeyPeer)
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	const EC_KEY* ecKey = reinterpret_cast<const EC_KEY*>(EVP_PKEY_get0(pKey));
	if (!ecKey)
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	auto field_size = EC_GROUP_get_degree(EC_KEY_get0_group(ecKey));
	size_t secretLength = (field_size + 7) / 8;

	vector<uint8_t> secret(secretLength);

	// Derive the shared secret
	// текущий rtengine не поддерживает ECDH на кривых ГОСТ 
	secretLength = ECDH_compute_key(secret.data(), secretLength, EC_KEY_get0_public_key(ecKeyPeer), ecKey, NULL);
	if (!secretLength)
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	return secret;
}

vector<uint8_t> OsslGostKeyPair::vko(const RtEngine& engine, const vector<uint8_t>& publicKey, const vector<uint8_t>& ukm) const
{
	// импорт публичного ключа токена в Openssl
	OsslGostKeyPair pairTemp(engine, getType(), getParamset());

	unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
	if (!memBio)
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	if (!i2d_PUBKEY_bio(memBio.get(), pairTemp))
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	BUF_MEM *mem = NULL;
	BIO_get_mem_ptr(memBio.get(), &mem);
	if (!mem)
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	memcpy(mem->data + mem->length - publicKey.size(), publicKey.data(), publicKey.size());

	if (!d2i_PUBKEY_bio(memBio.get(), pairTemp))
		throw runtime_error(ERR_error_string(ERR_get_error(), NULL));


	// Derive VKO for GOST
	// Create the context for the shared secret derivation
	unique_ptr<EVP_PKEY_CTX, decltype(EVP_PKEY_CTX_free)*> ctx(EVP_PKEY_CTX_new(pKey, NULL), EVP_PKEY_CTX_free);
	if (!ctx)
	    throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
	
	// Initialise
	if (!EVP_PKEY_derive_init(ctx.get()))
	    throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	if (!EVP_PKEY_CTX_ctrl(ctx.get(), -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_SET_IV, ukm.size(), (const_cast<vector<uint8_t>&>(ukm)).data()))
	    throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
	
	// Provide the peer public key
	if (!EVP_PKEY_derive_set_peer(ctx.get(), pairTemp))
	    throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	// Determine buffer length for shared secret
	size_t secretLength;
	if (!EVP_PKEY_derive(ctx.get(), NULL, &secretLength))
	    throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	vector<uint8_t> secret(secretLength);

	// Derive the shared secret
	if (!EVP_PKEY_derive(ctx.get(), secret.data(), &secretLength))
	    throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

	return secret;
}

OsslDigest::Algorithm OsslKeyPair::getDefaultDigestAlg() const
{
    int keyNid;
    if (!EVP_PKEY_get_default_digest_nid(pKey, &keyNid))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    return OsslDigest::nidToAlg(keyNid);
}

vector<uint8_t> OsslKeyPair::getPublicKeyDer() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!i2d_PUBKEY_bio(memBio.get(), pKey))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));


    vector<uint8_t> result(reinterpret_cast<uint8_t*>(mem->data), reinterpret_cast<uint8_t*>(mem->data + mem->length));
    return result;
}

vector<uint8_t> OsslKeyPair::getPrivateKeyDer() const
{
    unique_ptr<BIO, decltype(BIO_free)*> memBio(BIO_new(BIO_s_mem()), BIO_free);
    if (!memBio)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!i2d_PrivateKey_bio(memBio.get(), pKey))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    BUF_MEM *mem = NULL;
    BIO_get_mem_ptr(memBio.get(), &mem);
    if (!mem)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));


    vector<uint8_t> result(reinterpret_cast<uint8_t*>(mem->data), reinterpret_cast<uint8_t*>(mem->data + mem->length));
    return result;
}

void OsslKeyPair::WritePrivateKeyToPemFile(const string& file)
{
    unique_ptr<FILE, decltype(fclose)*> pemFile(fopen(file.c_str(), "wb"), fclose);
    if (!pemFile)
        throw runtime_error("Fopen for write failed");

    if (!PEM_write_PrivateKey(pemFile.get(), pKey, NULL, NULL, 0, NULL, NULL))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}

void OsslKeyPair::WritePublicKeyToPemFile(const string& file)
{
    unique_ptr<FILE, decltype(fclose)*> pemFile(fopen(file.c_str(), "wb"), fclose);
    if (!pemFile)
        throw runtime_error("Fopen for write failed");

    if (!PEM_write_PUBKEY(pemFile.get(), pKey))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}

OsslRsaKeyPair::OsslRsaKeyPair(size_t length) : OsslKeyPair(rsa)
{
    unique_ptr<EVP_PKEY_CTX, decltype(EVP_PKEY_CTX_free)*> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL), EVP_PKEY_CTX_free);
    if (!ctx)
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_PKEY_keygen_init(ctx.get()))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
    
    if (!EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), length))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));

    if (!EVP_PKEY_keygen(ctx.get(), &pKey))
        throw runtime_error(ERR_error_string(ERR_get_error(), NULL));
}