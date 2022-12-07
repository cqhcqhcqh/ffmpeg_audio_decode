#ifndef DECODETHREAD_H
#define DECODETHREAD_H

#include <QThread>
extern "C" {
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/avutil.h>
}

typedef struct {
    AVChannelLayout channel_layout;
    AVSampleFormat fmt;
    int bytesPerSample;
    int sample_rate = 0;
    const char *file;
} AudioDecodeSpec;

class DecodeThread : public QThread
{
    Q_OBJECT
private:
    void run() override;
public:
    DecodeThread(QObject *parent);
    ~DecodeThread();
signals:

};

#endif // DECODETHREAD_H
