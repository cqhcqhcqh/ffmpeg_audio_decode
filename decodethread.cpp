#include "decodethread.h"
#include <QDebug>
#include <QFile>

#ifdef Q_OS_MAC
#define IN_FILE "/Users/caitou/Desktop/in.aac"
#define OUT_FILE "/Users/caitou/Desktop/out.pcm"
#else
#define IN_FILE "C:\\Workspaces\\in.aac"
#define OUT_FILE "C:\\Workspaces\\out.pcm"
#endif
#define READ_AAC_DATA_SIZE 20480
// 需要再次读取输入文件数据的阈值
#define REFILL_THRESH 4096
#define ERROR_BUF(res) \
    char errbuf[1024]; \
    av_strerror(res, errbuf, sizeof(errbuf)); \

DecodeThread::DecodeThread(QObject *parent) : QThread(parent) {
    connect(this, &QThread::finished, this, &QThread::deleteLater);
}

DecodeThread::~DecodeThread() {
    disconnect();
    requestInterruption();
    quit();
    wait();

    qDebug() << "DecodeThread::~DecodeThread()";
}

static int check_sample_fmt(const AVCodec *codec,
                            enum AVSampleFormat sample_fmt)
{
    const enum AVSampleFormat *p = codec->sample_fmts;
    if (p == nullptr) return 1;
    while (*p != AV_SAMPLE_FMT_NONE) {
        qDebug() << "fmt: " << av_get_sample_fmt_name(*p);
        if (*p == sample_fmt)
            return 1;
        p++;
    }
    return 0;
}

int audio_decode(AVCodecContext *ctx, AVFrame *frame, AVPacket *packet, QFile &out) {
    /// 这里只需要 send 一次（全量）
    int res = avcodec_send_packet(ctx, packet);
    if (res < 0) {
        ERROR_BUF(res);
        qDebug() << "avcodec_send_packet err:" << errbuf;
        return res;
    }
    qDebug() << "avcodec_send_packet success";

    /* read all the available output packets (in general there may be any
         * number of them */
    /// 这里需要批量的 receive？
    while (true) {
        res = avcodec_receive_frame(ctx, frame);
        // EAGAIN: output is not available in the current state - user must try to send input
        // AVERROR_EOF: the encoder has been fully flushed, and there will be no more output packets
        // 退出函数，重新走 send 流程
        if (res == AVERROR(EAGAIN) || res == AVERROR_EOF) {
           return 0;
        } else if (res < 0) {
           ERROR_BUF(res);
           qDebug() << "avcodec_receive_frame error" << errbuf;
           return res;
        }
        qDebug() << "avcodec_receive_packet success receive frame line size: " << frame->linesize[0];
        out.write((char *) frame->data[0], frame->linesize[0]);
    }
}

/// PCM => AAC
void DecodeThread::run() {
    AudioDecodeSpec inSpec;
    inSpec.file = IN_FILE;

    AudioDecodeSpec outSpec;
    outSpec.file = OUT_FILE;
    outSpec.fmt = AV_SAMPLE_FMT_S16;

    char aacFileData[READ_AAC_DATA_SIZE + AV_INPUT_BUFFER_PADDING_SIZE] = { 0 };
    char *inData = aacFileData;
    int in_len = READ_AAC_DATA_SIZE;

    const AVCodec *codec = nullptr;
    AVCodecContext *ctx = nullptr;
    AVCodecParserContext *parserCtx = nullptr;
    AVFrame *frame = nullptr;
    AVPacket *packet = nullptr;
    QFile aac(IN_FILE);
    QFile pcm(OUT_FILE);
    int res = 0;

    codec = avcodec_find_decoder_by_name("libfdk_aac");
    if (codec == nullptr) {
        qDebug() << "avcodec_find_encoder_by_name failure";
        return;
    }

    qDebug() << codec->name;

    if (!check_sample_fmt(codec, outSpec.fmt)) {
        qDebug() << "check_sample_fmt not support pcm fmt" << av_get_sample_fmt_name(outSpec.fmt);
        goto end;
    }

    parserCtx = av_parser_init(codec->id);
    if (parserCtx == nullptr) {
        qDebug() << "av_parser_init failure";
        return;
    }

    ctx = avcodec_alloc_context3(codec);
    if (ctx == nullptr) {
        qDebug() << "avcodec_alloc_context3 failure";
        return;
    }

    // 配置输出参数
    // ctx->sample_fmt = AV_SAMPLE_FMT_S16;
    // ctx->bit_rate = 32000; // 比特率
    // ctx->profile = FF_PROFILE_AAC_HE_V2; // 规格

    /**
     * Initialize the AVCodecContext to use the given AVCodec. Prior to using this
     * function the context has to be allocated with avcodec_alloc_context3().
     *
     * The functions avcodec_find_decoder_by_name(), avcodec_find_encoder_by_name(),
     * avcodec_find_decoder() and avcodec_find_encoder() provide an easy way for
     * retrieving a codec.
     *
     * 重点
     * @note Always call this function before using decoding routines (such as
     * @ref avcodec_receive_frame()).
     *
     * @code
     * av_dict_set(&opts, "b", "2.5M", 0);
     * codec = avcodec_find_decoder(AV_CODEC_ID_H264);
     * if (!codec)
     *     exit(1);
     *
     * context = avcodec_alloc_context3(codec);
     *
     * if (avcodec_open2(context, codec, opts) < 0)
     *     exit(1);
     * @endcode
     *
     * @param avctx The context to initialize.
     * @param codec The codec to open this context for. If a non-NULL codec has been
     *              previously passed to avcodec_alloc_context3() or
     *              for this context, then this parameter MUST be either NULL or
     *              equal to the previously passed codec.
     * @param options A dictionary filled with AVCodecContext and codec-private options.
     *                On return this object will be filled with options that were not found.
     *
     * @return zero on success, a negative value on error
     * @see avcodec_alloc_context3(), avcodec_find_decoder(), avcodec_find_encoder(),
     *      av_dict_set(), av_opt_find().
     */
    res = avcodec_open2(ctx, codec, nullptr);
    if (res < 0) {
        ERROR_BUF(res);
        qDebug() << "avcodec_open2 errbuf" << errbuf << "res" << res;
        goto end;
    }

    if (pcm.open(QFile::WriteOnly) == 0) {
        qDebug() << "pcm open failure file: " << outSpec.file;
        goto end;
    }

    if (aac.open(QFile::ReadOnly) == 0) {
        qDebug() << "aac open failure file: " << inSpec.file;
        goto end;
    }

    /* frame containing input raw audio */
    frame = av_frame_alloc();
    if (frame == nullptr) {
        qDebug() << "av_frame_alloc failure";
        goto end;
    }

    packet = av_packet_alloc();
    if (packet == nullptr) {
        qDebug() << "av_packet_alloc failure";
        goto end;
    }

    in_len = aac.read(aacFileData, READ_AAC_DATA_SIZE);
    while (in_len > 0) {
        int parse_len = av_parser_parse2(parserCtx,
                         ctx,
                         (uint8_t **) &packet->data,
                         &packet->size,
                         (uint8_t *) inData,
                         in_len,
                         AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);
        inData += parse_len;
        in_len -= parse_len;
        qDebug() << "packet size" << packet->size;

        /// 将解码出来的 packet 写入到 frame 中，再将 frame 的数据写入 pcm 文件中
        int ret = audio_decode(ctx, frame, packet, pcm);
        if (ret < 0) {
            goto end;
        }

        if (in_len < REFILL_THRESH) {
            /// 将 inData 的数据搬移到 aacFileData 所在的地址空间
            memmove(aacFileData, inData, in_len);
            /// 继续从 aac 文件中读取 aac 数据至 aacFileData 偏移 in_len 的地址空间
            res = aac.read(aacFileData + in_len, READ_AAC_DATA_SIZE - in_len);
            /// 改变 inData 的指针地址（继续从头开始解码）
            inData = aacFileData;
            in_len += res;
        }
    }

    /*
     * It can be NULL, in which case it is considered a flush packet.
     * This signals the end of the stream. If the encoder
     * still has packets buffered, it will return them after this
     * call. Once flushing mode has been entered, additional flush
     * packets are ignored, and sending frames will return
     * AVERROR_EOF.
    */
    qDebug() << "flush packet";
    audio_decode(ctx, frame, nullptr, pcm);
end:
    pcm.close();
    aac.close();
    av_frame_free(&frame);
    av_packet_free(&packet);
    avcodec_free_context(&ctx);
    av_parser_close(parserCtx);
}
