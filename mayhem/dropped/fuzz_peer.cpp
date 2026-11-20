// DROPPED TARGET, NOT BUILT. build.sh does not compile this file; it is kept so a follow-up can restore it.
// Mayhem's symbolic-execution engine exited abnormally on fuzz-peer in 3 of 4 runs (latest: run 4 on
// 637995cd, SE log se-log-1795204527), and the cause could not be read from here. To restore: move this
// file back to mayhem/harnesses/, add fuzz_peer to TARGETS in build.sh, add Mayhemfile_fuzz_peer and its
// .github/workflows/mayhem.yml matrix entry, and reseed mayhem/fuzz_peer/testsuite (git history of the
// "Mayhem integration" commit at 637995cd has the earlier Mayhemfile and seeds).
//
// Fuzzes the core<->client wire protocol as a peer receives it from the network: RemotePeer framing
// (4-byte big-endian length + payload), zlib stream decompression (Compressor), then
// DataStreamPeer or LegacyPeer message decoding (handshake messages: RegisterClient, Login, SetupData,
// SessionState, ...; and, once a SignalProxy is attached, packed Sync/RpcCall/InitRequest/InitData/
// HeartBeat messages dispatched into SignalProxy::handle and a synced Network object).
// This is what a core parses from a not-yet-authenticated client, and what a client parses from a core.
//
// Byte 0: bit 0 = DataStreamPeer (else LegacyPeer), bit 1 = the rest is the raw zlib stream as received
// (fuzzes inflate on malformed streams), else the rest is the decompressed byte stream the peer decodes,
// bit 2 = attach a SignalProxy (bit 3: server mode, else client mode). The stream is followed by the
// remote end closing the connection.
//
// The peer always runs with compression on. Without it, Compressor::readData reads the socket with
// QIODevice::read(maxBufferSize), which allocates a 64 MiB QByteArray on every read: ~3 ms per input
// under ASan (the SE aborts above persisted after this was fixed, so it was not their cause). So a
// plain stream (bit 1 clear) is wrapped by the harness in zlib *stored* blocks (level 0: the bytes are
// copied verbatim, no compression search) before the peer reads it; the peer's inflate hands exactly
// those bytes to RemotePeer. Only the three-line NoCompression branch of Compressor::readData is lost.
//
// The connection is an in-memory QTcpSocket (MemSocket below) in the ConnectedState: the peer and its
// Compressor read it through the ordinary QIODevice/QAbstractSocket interface and are woken by its
// readyRead() signal, exactly as with a network socket, but no QCoreApplication, event loop or real
// socket is involved (an event dispatcher makes Mayhem's symbolic executor abort the whole run).
#include <QByteArray>
#include <QCoreApplication>
#include <QHostAddress>
#include <QPointer>
#include <QTcpSocket>

#include <algorithm>
#include <cstring>
#include <memory>

#include <zlib.h>

#include "authhandler.h"
#include "compressor.h"
#include "network.h"
#include "protocols/datastream/datastreampeer.h"
#include "protocols/legacy/legacypeer.h"
#include "signalproxy.h"

#include "fuzz_common.h"

namespace {

// Accepts every handshake message (the default AuthHandler closes the connection on any message),
// so a session can proceed past the first message.
class FuzzAuthHandler : public AuthHandler
{
public:
    using AuthHandler::AuthHandler;
    void handle(const Protocol::RegisterClient&) override {}
    void handle(const Protocol::ClientDenied&) override {}
    void handle(const Protocol::ClientRegistered&) override {}
    void handle(const Protocol::SetupData&) override {}
    void handle(const Protocol::SetupFailed&) override {}
    void handle(const Protocol::SetupDone&) override {}
    void handle(const Protocol::Login&) override {}
    void handle(const Protocol::LoginFailed&) override {}
    void handle(const Protocol::LoginSuccess&) override {}
    void handle(const Protocol::SessionState&) override {}
};

// A connected TCP socket whose incoming bytes are a fixed buffer; writes are accepted and discarded.
class MemSocket : public QTcpSocket
{
public:
    explicit MemSocket(const QByteArray& in)
        : _in(in)
    {
        setPeerAddress(QHostAddress::LocalHost);
        setPeerPort(4242);
        setSocketState(QAbstractSocket::ConnectedState);
        setOpenMode(QIODevice::ReadWrite | QIODevice::Unbuffered);
    }

    qint64 remaining() const { return _in.size() - _pos; }
    qint64 bytesAvailable() const override { return QIODevice::bytesAvailable() + remaining(); }
    qint64 bytesToWrite() const override { return 0; }
    bool waitForReadyRead(int) override { return false; }
    bool waitForBytesWritten(int) override { return false; }

    // The remote end closed the connection (as QAbstractSocket reports it): state change, disconnected().
    void remoteClose()
    {
        if (state() == QAbstractSocket::UnconnectedState)
            return;
        setSocketState(QAbstractSocket::UnconnectedState);
        emit stateChanged(QAbstractSocket::UnconnectedState);
        emit disconnected();
    }
    void close() override
    {
        remoteClose();
        QIODevice::close();
    }

protected:
    qint64 readData(char* buf, qint64 maxlen) override
    {
        const qint64 n = std::min(maxlen, remaining());
        if (n > 0) {
            memcpy(buf, _in.constData() + _pos, static_cast<size_t>(n));
            _pos += n;
        }
        return n;
    }
    qint64 writeData(const char*, qint64 len) override { return len; }

private:
    QByteArray _in;
    qint64 _pos{0};
};

// Wraps a plain byte stream in a zlib stream of stored (uncompressed) blocks, sync-flushed and not
// finished, as a compressing peer that has sent all of it but not closed its stream would.
QByteArray storedZlibStream(const uint8_t* data, size_t size)
{
    z_stream zs;
    memset(&zs, 0, sizeof(zs));
    if (deflateInit(&zs, Z_NO_COMPRESSION) != Z_OK)
        abort();
    QByteArray out;
    out.resize(static_cast<int>(deflateBound(&zs, size) + 64));
    zs.next_in = const_cast<Bytef*>(data);
    zs.avail_in = static_cast<uInt>(size);
    zs.next_out = reinterpret_cast<Bytef*>(out.data());
    zs.avail_out = static_cast<uInt>(out.size());
    if (deflate(&zs, Z_SYNC_FLUSH) != Z_OK || zs.avail_in != 0)
        abort();
    out.resize(static_cast<int>(zs.total_out));
    deflateEnd(&zs);
    return out;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzzInitQt();
    if (size < 1)
        return 0;
    const uint8_t sel = data[0];

    auto* sock = new MemSocket((sel & 2) ? QByteArray(reinterpret_cast<const char*>(data + 1), static_cast<int>(size - 1))
                                         : storedZlibStream(data + 1, size - 1));
    auto* auth = new FuzzAuthHandler;
    const auto level = Compressor::BestCompression;
    RemotePeer* peer;
    if (sel & 1)
        peer = new DataStreamPeer(auth, sock, 0, level);
    else
        peer = new LegacyPeer(auth, sock, level);
    sock->setParent(peer);
    QPointer<RemotePeer> guard(peer);
    QPointer<MemSocket> sockGuard(sock);

    std::unique_ptr<SignalProxy> proxy;
    std::unique_ptr<Network> network;
    if (sel & 4) {
        proxy.reset(new SignalProxy((sel & 8) ? SignalProxy::Server : SignalProxy::Client, nullptr));
        network.reset(new Network(NetworkId(1)));
        network->setProxy(proxy.get());
        network->setRejoinChannels(true);  // Network's ctor leaves it uninitialized
        network->setNetworkInfo(NetworkInfo{});
        proxy->synchronize(network.get());
        proxy->addPeer(peer);
    }

    // Deliver the stream: each readyRead() lets the Compressor and RemotePeer::onReadyRead consume what
    // they want, as when more data arrives on a socket. Stop when the peer stops consuming or is gone.
    while (sockGuard && sockGuard->state() == QAbstractSocket::ConnectedState && sockGuard->remaining() > 0) {
        const qint64 before = sockGuard->remaining();
        emit sockGuard->readyRead();
        if (!sockGuard || sockGuard->remaining() == before)
            break;
    }
    if (sockGuard)
        sockGuard->remoteClose();  // EOF after the input

    if (proxy)
        proxy->stopSynchronize(network.get());
    proxy.reset();  // ~SignalProxy removes its peers (deleteLater)
    network.reset();
    // Flush posted events (RemovePeerEvent, deleteLater()s) so nothing from this input survives.
    QCoreApplication::sendPostedEvents(nullptr, 0);
    QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    if (guard)
        delete guard.data();
    delete auth;
    return 0;
}
