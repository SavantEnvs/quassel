// Fuzzes how a client applies the InitData a (possibly malicious) core sends for synced objects:
// the QVariantMap is decoded with the real wire deserializer (Serializers::deserialize, as DataStreamPeer
// does) and handed to SyncableObject::fromVariantMap, which dispatches to each class's initSet*
// handlers: Network (IrcUsersAndChannels -> IrcUser/IrcChannel creation and user modes, Supports,
// Caps, ServerList), BufferViewConfig, IgnoreListManager and HighlightRuleManager. (No toVariantMap():
// that is the core's producer side and asserts it runs on the core.)
// Byte 0 picks the object class (mod 4); the rest is the serialized QVariantMap.
// As on a real client, the object is synchronized to a client-mode SignalProxy and the InitData is
// applied with a source peer set (Network::initSetIrcUsersAndChannels asserts both). The proxy and
// peer persist across inputs; each input's object is unregistered and destroyed before the next, so
// no per-input state survives. No QCoreApplication: nothing on this path needs an event loop, and
// one (its event dispatcher) makes Mayhem's symbolic executor abort the whole run.
#include <QByteArray>
#include <QDataStream>
#include <QVariant>

#include <memory>

#include "bufferviewconfig.h"
#include "highlightrulemanager.h"
#include "internalpeer.h"
#include "ignorelistmanager.h"
#include "network.h"
#include "quassel.h"
#include "serializers/serializers.h"
#include "signalproxy.h"

#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzzInitQt();
    static SignalProxy proxy(SignalProxy::Client, nullptr);
    static InternalPeer peer;
    if (size < 1)
        return 0;
    const uint8_t sel = data[0];
    QByteArray buf(reinterpret_cast<const char*>(data + 1), static_cast<int>(size - 1));
    QDataStream stream(buf);
    stream.setVersion(QDataStream::Qt_4_2);
    QVariantMap map;
    if (!Serializers::deserialize(stream, Quassel::Features{}, map))
        return 0;

    std::unique_ptr<SyncableObject> obj;
    switch (sel % 4) {
    case 0: {
        auto* net = new Network(NetworkId(1));
        net->setProxy(&proxy);  // as Client::coreNetworkCreated / ClientSyncer do
        // Network's constructor leaves some settings (e.g. _rejoinChannels) uninitialized; a real peer's
        // InitData always carries every property. Start from default NetworkInfo so later reads only
        // see values that are either defaults or came from this input.
        net->setRejoinChannels(true);  // plain store; setNetworkInfo() would compare the uninitialized value
        net->setNetworkInfo(NetworkInfo{});
        obj.reset(net);
        break;
    }
    case 1:
        obj.reset(new BufferViewConfig(1));
        break;
    case 2:
        obj.reset(new IgnoreListManager());
        break;
    default:
        obj.reset(new HighlightRuleManager());
        break;
    }
    proxy.synchronize(obj.get());
    proxy.setSourcePeer(&peer);
    obj->fromVariantMap(map);
    proxy.setSourcePeer(nullptr);
    proxy.stopSynchronize(obj.get());
    return 0;
}
