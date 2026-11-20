// Fuzzes the raw IRC line parser (src/common/ircdecoder.cpp): IRCv3 message tags + unescaping, prefix,
// command and parameters of a line received from an IRC server, then re-encodes the parsed message
// with IrcEncoder::writeMessage (the core's outgoing path) as a round trip.
#include <QByteArray>
#include <QHash>
#include <QList>
#include <QString>

#include "ircdecoder.h"
#include "ircencoder.h"
#include "irctag.h"

#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzzInitQt();
    QByteArray raw(reinterpret_cast<const char*>(data), static_cast<int>(size));
    QHash<IrcTagKey, QString> tags;
    QString prefix;
    QString command;
    QList<QByteArray> params;
    IrcDecoder::parseMessage([](const QByteArray& s) { return QString::fromUtf8(s); }, raw, tags, prefix, command, params);
    QByteArray out = IrcEncoder::writeMessage(tags, prefix.toUtf8(), command, params);
    (void)out.size();
    return 0;
}
