// Fuzzes the IRC-derived string helpers in src/common/util.cpp: charset auto-detection
// (decodeString, UTF-8 vs locale fallback), mIRC format-code stripping, hostmask splitting, channel
// name detection and epoch-timestamp formatting of server-supplied text (tryFormatUnixEpoch).
#include <cstring>

#include <QByteArray>
#include <QString>

#include "util.h"

#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzzInitQt();
    QByteArray raw(reinterpret_cast<const char*>(data), static_cast<int>(size));
    const QString s = decodeString(raw);
    (void)stripFormatCodes(s);
    (void)nickFromMask(s);
    (void)userFromMask(s);
    (void)hostFromMask(s);
    (void)isChannelName(s);
    (void)tryFormatUnixEpoch(s, Qt::DefaultLocaleShortDate, false);
    (void)tryFormatUnixEpoch(s, Qt::ISODate, true);
    if (size >= 4) {
        int secs;
        memcpy(&secs, data, sizeof secs);
        (void)secondsToString(secs);
    }
    return 0;
}
