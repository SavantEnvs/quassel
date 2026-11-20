// Fuzzes ProxyLine::parseProxyLine (src/common/proxyline.cpp), the HAProxy PROXY v1 header parser that
// CoreAuthHandler::onReadyRead runs on the first line a not-yet-authenticated client sends.
#include <QByteArray>

#include "proxyline.h"

#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzzInitQt();
    ProxyLine line = ProxyLine::parseProxyLine(QByteArray(reinterpret_cast<const char*>(data), static_cast<int>(size)));
    (void)line.sourceHost.toString();
    (void)line.targetHost.toString();
    return 0;
}
