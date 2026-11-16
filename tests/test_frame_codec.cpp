// FrameCodec 单元测试：编码字节布局、半包、粘包、非法帧头、长度上限。
#include <gtest/gtest.h>

#include "common/frame_codec.h"

using namespace fwds;

namespace {

QByteArray encode(quint8 type, quint64 seq, const QByteArray& body) {
  QByteArray out;
  EXPECT_TRUE(encodeFrame(type, seq, body, &out));
  return out;
}

}  // namespace

TEST(FrameCodec, EncodeLayoutMatchesProtocol) {
  const QByteArray wire = encode(0x10, 0x0102030405060708ULL, QByteArray("abc"));
  ASSERT_EQ(wire.size(), kHeaderSize + 3);
  // Magic "FW"、版本 2、类型、8 字节大端序号、4 字节大端长度
  EXPECT_EQ(wire.left(16).toHex(), QByteArray("46570210010203040506070800000003"));
  EXPECT_EQ(wire.mid(16), QByteArray("abc"));
}

TEST(FrameCodec, EncodeRejectsOversizedBody) {
  QByteArray out("keep");
  EXPECT_FALSE(encodeFrame(0x23, 1, QByteArray(11, 'x'), &out, 10));
  EXPECT_EQ(out, QByteArray("keep"));  // 失败时不改动输出
}

TEST(FrameCodec, DecodeSingleFrame) {
  FrameDecoder decoder;
  decoder.feed(encode(0x01, 1, QByteArray("{\"a\":1}")));
  Frame frame;
  ASSERT_EQ(decoder.next(&frame), DecodeStatus::FrameReady);
  EXPECT_EQ(frame.type, 0x01);
  EXPECT_EQ(frame.seq, 1u);
  EXPECT_EQ(frame.body, QByteArray("{\"a\":1}"));
  EXPECT_EQ(decoder.next(&frame), DecodeStatus::NeedMore);
  EXPECT_EQ(decoder.buffered(), 0);
}

TEST(FrameCodec, EmptyBodyIsValid) {
  FrameDecoder decoder;
  decoder.feed(encode(0x7E, 5, QByteArray()));
  Frame frame;
  ASSERT_EQ(decoder.next(&frame), DecodeStatus::FrameReady);
  EXPECT_TRUE(frame.body.isEmpty());
}

// 半包：一个字节一个字节地喂，最后一个字节到达前都应是 NeedMore
TEST(FrameCodec, HalfPacketWaitsForMoreData) {
  const QByteArray wire = encode(0x22, 7, QByteArray("hello world"));
  FrameDecoder decoder;
  Frame frame;
  for (qsizetype i = 0; i < wire.size() - 1; ++i) {
    decoder.feed(wire.mid(i, 1));
    ASSERT_EQ(decoder.next(&frame), DecodeStatus::NeedMore) << "at byte " << i;
  }
  decoder.feed(wire.right(1));
  ASSERT_EQ(decoder.next(&frame), DecodeStatus::FrameReady);
  EXPECT_EQ(frame.seq, 7u);
  EXPECT_EQ(frame.body, QByteArray("hello world"));
}

// 粘包：三帧加第四帧的前半截一次到达
TEST(FrameCodec, StickyPacketsAreSplit) {
  const QByteArray fourth = encode(0x30, 4, QByteArray("dddd"));
  QByteArray stream = encode(0x10, 1, QByteArray("a")) + encode(0x10, 2, QByteArray()) +
                      encode(0x30, 3, QByteArray("ccc")) + fourth.left(10);
  FrameDecoder decoder;
  decoder.feed(stream);
  Frame frame;
  for (quint64 seq = 1; seq <= 3; ++seq) {
    ASSERT_EQ(decoder.next(&frame), DecodeStatus::FrameReady);
    EXPECT_EQ(frame.seq, seq);
  }
  EXPECT_EQ(frame.body, QByteArray("ccc"));
  ASSERT_EQ(decoder.next(&frame), DecodeStatus::NeedMore);
  decoder.feed(fourth.mid(10));
  ASSERT_EQ(decoder.next(&frame), DecodeStatus::FrameReady);
  EXPECT_EQ(frame.seq, 4u);
  EXPECT_EQ(frame.body, QByteArray("dddd"));
}

TEST(FrameCodec, BadMagicIsRejected) {
  QByteArray wire = encode(0x10, 1, QByteArray("x"));
  wire[0] = 'G';
  FrameDecoder decoder;
  decoder.feed(wire);
  Frame frame;
  EXPECT_EQ(decoder.next(&frame), DecodeStatus::Error);
  EXPECT_EQ(decoder.error(), ErrorCode::BadMagic);
}

TEST(FrameCodec, BadVersionIsRejected) {
  QByteArray wire = encode(0x10, 1, QByteArray("x"));
  wire[2] = 0x01;
  FrameDecoder decoder;
  decoder.feed(wire);
  Frame frame;
  EXPECT_EQ(decoder.next(&frame), DecodeStatus::Error);
  EXPECT_EQ(decoder.error(), ErrorCode::BadVersion);
}

// 只收到 16 字节帧头、Length 谎报 4 GB：必须立刻报 1003，而不是等待或分配内存
TEST(FrameCodec, OversizedLengthRejectedFromHeaderAlone) {
  const QByteArray header = QByteArray::fromHex("465702230000000000000001ffffffff");
  FrameDecoder decoder;
  decoder.feed(header);
  Frame frame;
  EXPECT_EQ(decoder.next(&frame), DecodeStatus::Error);
  EXPECT_EQ(decoder.error(), ErrorCode::FrameTooLarge);
  EXPECT_EQ(decoder.buffered(), 0);
}

TEST(FrameCodec, LengthBoundary) {
  // 恰好等于上限：合法
  FrameDecoder ok;
  ok.feed(encode(0x23, 1, QByteArray(static_cast<qsizetype>(kMaxBodyLength), 'z')));
  Frame frame;
  ASSERT_EQ(ok.next(&frame), DecodeStatus::FrameReady);
  EXPECT_EQ(frame.body.size(), static_cast<qsizetype>(kMaxBodyLength));

  // 上限加 1：非法（0x00100001）
  FrameDecoder bad;
  bad.feed(QByteArray::fromHex("46570223000000000000000100100001"));
  EXPECT_EQ(bad.next(&frame), DecodeStatus::Error);
  EXPECT_EQ(bad.error(), ErrorCode::FrameTooLarge);
}

// 出错之后一直是 Error，后续数据被丢弃
TEST(FrameCodec, ErrorIsSticky) {
  FrameDecoder decoder;
  decoder.feed(QByteArray(16, '\0'));
  Frame frame;
  ASSERT_EQ(decoder.next(&frame), DecodeStatus::Error);
  decoder.feed(encode(0x10, 1, QByteArray("x")));
  EXPECT_EQ(decoder.next(&frame), DecodeStatus::Error);
  EXPECT_EQ(decoder.error(), ErrorCode::BadMagic);
  EXPECT_EQ(decoder.buffered(), 0);
}

// 连续解析很多帧，覆盖缓冲区整理的路径
TEST(FrameCodec, ManyFramesAcrossCompaction) {
  QByteArray stream;
  const int count = 300;
  for (int i = 1; i <= count; ++i) {
    stream += encode(0x23, static_cast<quint64>(i), QByteArray(1000, static_cast<char>('a' + i % 26)));
  }
  FrameDecoder decoder;
  Frame frame;
  int decoded = 0;
  // 按 7777 字节一段喂入，帧边界和分段边界错开
  for (qsizetype off = 0; off < stream.size(); off += 7777) {
    decoder.feed(stream.mid(off, 7777));
    while (decoder.next(&frame) == DecodeStatus::FrameReady) {
      ++decoded;
      ASSERT_EQ(frame.seq, static_cast<quint64>(decoded));
      ASSERT_EQ(frame.body, QByteArray(1000, static_cast<char>('a' + decoded % 26)));
    }
  }
  EXPECT_EQ(decoded, count);
  EXPECT_EQ(decoder.buffered(), 0);
}

TEST(Protocol, ClosesConnectionRule) {
  EXPECT_TRUE(closesConnection(1001));
  EXPECT_TRUE(closesConnection(1007));
  EXPECT_TRUE(closesConnection(2001));
  EXPECT_FALSE(closesConnection(1005));  // BAD_JSON 不断开
  EXPECT_FALSE(closesConnection(3013));
  EXPECT_FALSE(closesConnection(0));
}
