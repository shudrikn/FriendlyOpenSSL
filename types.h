#pragma once

#include <map>

#include <ossl_keyPair.h>
#include <ossl_cms.h>

#include <util/common.h>

static std::map <OsslKeyPair::Type, asymmAlg> osslKeyType = { { OsslKeyPair::gost2001, gost3410_2001 },{ OsslKeyPair::gost2012_256, gost3410_256 },{ OsslKeyPair::gost2012_512, gost3410_512 } };
static std::map <asymmAlg, OsslKeyPair::Type> tokenKeyType = { { gost3410_2001, OsslKeyPair::gost2001 },{ gost3410_256, OsslKeyPair::gost2012_256 },{ gost3410_512, OsslKeyPair::gost2012_512 } };
static std::map <OsslGostKeyPair::Paramset, gostParamset> osslParamset = { { OsslGostKeyPair::A, A },{ OsslGostKeyPair::B, B },{ OsslGostKeyPair::C, C } };
static std::map <gostParamset, OsslGostKeyPair::Paramset> tokenParamset = { { A, OsslGostKeyPair::A },{ B, OsslGostKeyPair::B },{ C, OsslGostKeyPair::C } };
static std::map <OsslDigest::Algorithm, hashAlg> osslDisgestAlgs = { { OsslDigest::gost94, gost3411_94 },{ OsslDigest::gost2012_256, gost3411_256 },{ OsslDigest::gost2012_512, gost3411_512 }, };
static std::map <hashAlg, OsslDigest::Algorithm> tokenDisgestAlgs = { { gost3411_94, OsslDigest::gost94 },{ gost3411_256, OsslDigest::gost2012_256 },{ gost3411_512, OsslDigest::gost2012_512 }, };