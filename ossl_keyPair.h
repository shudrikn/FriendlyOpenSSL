#pragma once
#include <vector>

#include "ossl_digest.h"
#include "ossl_request.h"
#include "noncopyable.h"

class RtEngine;
struct OsslReqConfig;
class OsslCertificate;

typedef struct evp_pkey_st EVP_PKEY;

class OsslKeyPair : public Noncopyable
{
public:
    enum Type { gost2001, gost2012_256, gost2012_512, rsa, types_end };
    static std::string typeToStr(Type type);
    static Type strToType(const std::string& str);

    friend Type& operator++ (Type& type);

protected:
    EVP_PKEY* pKey = nullptr;
    
    Type type;

    static bool verify( EVP_PKEY* pKey,
                        const std::vector<uint8_t>& data, 
                        const std::vector<uint8_t>& sign, 
                        const std::shared_ptr<OsslDigest::Algorithm>& digestAlg = nullptr,
                        const std::shared_ptr<RtEngine>& engine = nullptr);

public:
    enum FileType { privateKeyPem, publicKeyPem };
    OsslKeyPair(Type type) : type(type) {};
    OsslKeyPair(const std::string& file, FileType fileType = privateKeyPem);
    virtual ~OsslKeyPair();

    std::vector<uint8_t> rawSign(const std::vector<uint8_t>& data) const;
    virtual bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sign, const std::shared_ptr<OsslDigest::Algorithm>& digestAlg = nullptr) const;

	virtual std::vector<uint8_t> ecdh(const RtEngine& engine, const std::vector<uint8_t>& publicKey) const = 0;

    std::vector<uint8_t> getPublicKeyDer() const;
    std::vector<uint8_t> getPrivateKeyDer() const;
    OsslDigest::Algorithm getDefaultDigestAlg() const;

    operator EVP_PKEY*() const { return pKey; }
    operator EVP_PKEY**() { return &pKey; }
    Type getType() const { return type; }

    void WritePrivateKeyToPemFile(const std::string& file);
    void WritePublicKeyToPemFile(const std::string& file);
};

class OsslGostKeyPair : public OsslKeyPair
{
public:
    enum Paramset { A, B, C, TCA, TCB, TCC, TCD, paramsets_end };
    static std::string paramsetToStr(Type type, Paramset paramset);
    static int paramsetToNid(Type type, Paramset paramset);
    static Paramset strToParamset(const std::string& str);

    friend Paramset& operator++ (Paramset& paramset);

private:
    Paramset paramset;
    
public:
    
    OsslGostKeyPair(const RtEngine& engine, Type type = gost2012_256, Paramset paramset = B);
    ~OsslGostKeyPair() {};

    bool verify(const std::vector<uint8_t>& data, const std::vector<uint8_t>& sign, const std::shared_ptr<OsslDigest::Algorithm>& digestAlg = nullptr) const override
    {
        return OsslKeyPair::verify(data, sign, digestAlg);
    }

    // Публичный ключ передаётся в формате YX
    static bool verify( const RtEngine& engine,
                        const std::vector<uint8_t>& pubKeyValue, 
                        Type keyType, 
                        Paramset keyParamset, 
                        const std::vector<uint8_t>& data,
                        const std::vector<uint8_t>& sign, 
                        const std::shared_ptr<OsslDigest::Algorithm>& digestAlg = nullptr);

	std::vector<uint8_t> ecdh(const RtEngine& engine, const std::vector<uint8_t>& publicKey) const;
	std::vector<uint8_t> vko(const RtEngine& engine, const std::vector<uint8_t>& publicKey, const std::vector<uint8_t>& ukm) const;

    Paramset getParamset() const { return paramset; }
};

class OsslRsaKeyPair : public OsslKeyPair
{
public:
    OsslRsaKeyPair(size_t length = 2048);
    ~OsslRsaKeyPair() {};
};

inline OsslKeyPair::Type& operator++ (OsslKeyPair::Type& type)
{
    type = static_cast<OsslKeyPair::Type>(static_cast<int>(type) + 1);
    return type;
};

inline OsslGostKeyPair::Paramset& operator++ (OsslGostKeyPair::Paramset& paramset)
{
    paramset = static_cast<OsslGostKeyPair::Paramset>(static_cast<int>(paramset) + 1);
    return paramset;
};