package com.jetbrains.signatureverifier.tests;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ByteChannel;

class BinaryWriter {
  private final ByteChannel channel;
  private final ByteBuffer buffer = ByteBuffer.allocateDirect(8).order(ByteOrder.LITTLE_ENDIAN);

  BinaryWriter(ByteChannel channel) {
    this.channel = channel;
  }

  void Write(int value) throws IOException {
    buffer.clear();
    buffer.limit(Integer.BYTES);
    buffer.putInt(value);
    buffer.rewind();
    channel.write(buffer);
  }

  void Write(short value) throws IOException {
    buffer.clear();
    buffer.limit(Short.BYTES);
    buffer.putShort(value);
    buffer.rewind();
    channel.write(buffer);
  }

  void Write(byte[] array) throws IOException {
    channel.write(ByteBuffer.wrap(array));
  }
}
