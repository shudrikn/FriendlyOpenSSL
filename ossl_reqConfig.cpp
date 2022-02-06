#include "ossl_reqConfig.h"

OsslReqConfig::OsslReqConfig()
{
    version = 0;

    dn = {
        { "CN", "Tester" },
        { "1.2.840.113549.1.9.1", "shudrik@rutoken.ru" }
    };

    attrs = {
        { "1.8.2.21.1.43.41.236", "ASN1:FORMAT:UTF8,UTF8String:Moscow" },
        { "1.4.22.43", "test string 1" },
    };

    exts = {
        { "keyUsage", "cRLSign,keyCertSign,digitalSignature" },
        //{ "2.5.29.37", "DER:30:09:06:07:2A:85:03:03:7B:05:13" },   // OID для транспортного сертификата Сбербанка
        { "basicConstraints", "critical,CA:TRUE" },
        { "1.2.643.100.111", "ASN1:UTF8String:\xd0\xb0\xd0\xb1\xd0\xb2" },
    };
}