// Fuzzes ExpressionMatch (src/common/expressionmatch.cpp), the rule compiler behind highlight and
// ignore rules (which are synced over the wire) that is matched against incoming IRC text.
// Byte 0: bits 0-2 pick the MatchMode (mod 5), bit 3 case sensitivity, bit 4 matchEmpty.
// The rest is "<rule>\0<subject>" (UTF-8); with no NUL the whole rest is the rule.
#include <QByteArray>
#include <QString>

#include "expressionmatch.h"

#include "fuzz_common.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzzInitQt();
    if (size < 1)
        return 0;
    const uint8_t sel = data[0];
    QByteArray rest(reinterpret_cast<const char*>(data + 1), static_cast<int>(size - 1));
    const int nul = rest.indexOf('\0');
    const QString rule = QString::fromUtf8(nul < 0 ? rest : rest.left(nul));
    const QString subject = nul < 0 ? QString{} : QString::fromUtf8(rest.mid(nul + 1));
    const auto mode = static_cast<ExpressionMatch::MatchMode>((sel & 7) % 5);
    ExpressionMatch m(rule, mode, (sel & 8) != 0);
    if (m.isValid())
        (void)m.match(subject, (sel & 16) != 0);
    (void)ExpressionMatch::trimMultiWildcardWhitespace(rule);
    return 0;
}
