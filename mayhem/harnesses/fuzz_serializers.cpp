// Fuzzes Quassel's DataStream wire deserializer (src/common/serializers/serializers.cpp): the code that
// decodes every message a client/core peer sends (QVariant maps/lists carrying Message, BufferInfo,
// Identity, Network::Server, NetworkInfo, ids, dates, strings).
// Byte 0 selects the peer feature set (bit 0: all features vs none) and the top-level container
// (bit 1: QVariantMap vs QVariantList); the rest is the serialized stream as DataStreamPeer reads it.
#include <QByteArray>
#include <QDataStream>
#include <QStringList>
#include <QVariant>

#include "quassel.h"
#include "serializers/serializers.h"

#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzzInitQt();
    if (size < 1)
        return 0;
    const uint8_t sel = data[0];
    QByteArray buf(reinterpret_cast<const char*>(data + 1), static_cast<int>(size - 1));
    QDataStream stream(buf);
    stream.setVersion(QDataStream::Qt_4_2);  // as DataStreamPeer::processMessage
    const Quassel::Features features = (sel & 1) ? Quassel::Features{}
                                                 : Quassel::Features{QStringList{}, Quassel::LegacyFeatures{}};
    if (sel & 2) {
        QVariantMap map;
        if (Serializers::deserialize(stream, features, map))
            (void)map.keys();
    }
    else {
        QVariantList list;
        if (Serializers::deserialize(stream, features, list))
            for (const QVariant& v : list)
                (void)v.toString();
    }
    return 0;
}
