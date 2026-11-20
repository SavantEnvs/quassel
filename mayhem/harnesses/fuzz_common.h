// Shared harness setup: silence Qt's qDebug/qWarning output on malformed input (speed only; a
// process-global, read-only setting installed once and never changed by an input).
#pragma once
#include <QtGlobal>
#include <QString>
#include <cstddef>
#include <cstdint>

static void fuzzQuietHandler(QtMsgType type, const QMessageLogContext&, const QString& msg)
{
    // Keep Qt's own fatal semantics: qFatal must still abort so it is reported as a crash.
    if (type == QtFatalMsg) {
        fprintf(stderr, "qFatal: %s\n", msg.toLocal8Bit().constData());
        abort();
    }
}

static inline void fuzzInitQt()
{
    static bool done = false;
    if (!done) {
        qInstallMessageHandler(fuzzQuietHandler);
        done = true;
    }
}
