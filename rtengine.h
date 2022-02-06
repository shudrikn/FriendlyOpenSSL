#pragma once

#include "engine.h"
#include <memory>

class RtEngine
{
public:

    static RtEngine& getInstance() { return instance; };

    operator ENGINE*() const { return m_engine; };

private:

    static RtEngine instance;

    RtEngine();
    ~RtEngine();

    bool initializeEngine();
    bool uninitializeEngine();

    ENGINE* m_engine;

    RtEngine(const RtEngine&);
    void operator=(const RtEngine&);
};
