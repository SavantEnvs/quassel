// Fuzzes the FiSH/DH1080 code in the core (src/core/cipher.cpp) that handles peer-supplied IRC
// payloads: "+OK "/"mcps " blowfish ECB/CBC message and topic decryption (incl. FiSH's own base64),
// and the DH1080_INIT / DH1080_FINISH key-exchange NOTICE parsers.
// Byte 0: bits 0-1 pick the operation, bit 2 prefixes the key with "cbc:" (CBC mode). For decryption
// the rest is "<key>\0<ciphertext>"; for the key exchange it is the peer's NOTICE payload.
#include <QByteArray>

#include <QtCrypto>

#include "cipher.h"

#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    static QCA::Initializer qcaInit;  // process-wide QCA plugin registry, read-only after init
    fuzzInitQt();
    if (size < 1)
        return 0;
    const uint8_t sel = data[0];
    QByteArray rest(reinterpret_cast<const char*>(data + 1), static_cast<int>(size - 1));
    switch (sel & 3) {
    case 0:
    case 1: {
        const int nul = rest.indexOf('\0');
        if (nul < 0)
            return 0;
        QByteArray key = ((sel & 4) ? QByteArray("cbc:") : QByteArray()) + rest.left(nul);
        Cipher c(key);
        QByteArray msg = rest.mid(nul + 1);
        if (sel & 1)
            (void)c.decryptTopic(msg);
        else
            (void)c.decrypt(msg);
        break;
    }
    case 2: {
        Cipher c;
        (void)c.parseInitKeyX(rest);
        break;
    }
    default: {
        Cipher c;
        (void)c.initKeyExchange((sel & 4) != 0);
        (void)c.parseFinishKeyX(rest);
        break;
    }
    }
    return 0;
}
