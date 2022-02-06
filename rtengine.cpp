#include <stdexcept>

#include "rtengine.h"

using namespace std;

RtEngine RtEngine::instance;

RtEngine::RtEngine() : m_engine(NULL)
{
    if (!initializeEngine())
        throw runtime_error("Failed to start Rutoken Engine : " + string(ERR_error_string(ERR_get_error(), NULL)));
}

RtEngine::~RtEngine()
{
    uninitializeEngine();
}

bool RtEngine::initializeEngine()
{
    if (!OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_NO_LOAD_CONFIG, NULL))
    {
        return false;
    }

    if (!rt_eng_load_engine())
    {
        return false;
    }

    if ((m_engine = rt_eng_get0_engine()) == NULL)
    {
        rt_eng_unload_engine();
        return false;
    }

    if (!ENGINE_set_default(m_engine, ENGINE_METHOD_ALL - ENGINE_METHOD_RAND))
    {
        rt_eng_unload_engine();
        m_engine = NULL;
        return false;
    }

    return true;
}

bool RtEngine::uninitializeEngine()
{
    if (m_engine)
    {
        ENGINE_unregister_pkey_asn1_meths(m_engine);
        ENGINE_unregister_pkey_meths(m_engine);
        ENGINE_unregister_digests(m_engine);
        ENGINE_unregister_ciphers(m_engine);

        if (rt_eng_unload_engine())
            m_engine = NULL;
        else
            return false;
    }

    return true;
}