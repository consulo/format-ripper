package com.jetbrains.util.filetype.io;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ByteChannel;
import java.nio.charset.StandardCharsets;

public class BinaryReader {
  private final ByteChannel channel;
  /** Reusable buffer */
  private final ByteBuffer buffer = ByteBuffer.allocateDirect(8).order(ByteOrder.LITTLE_ENDIAN);

  public BinaryReader(ByteChannel channel) {
    this.channel = channel;
  }

  public ByteChannel getBaseStream() {
    return channel;
  }

  public byte readByte() throws IOException {
    fill(1);
    return buffer.get(0);
  }

  /** Returns the 4 bytes as an int (unsigned 32-bit value in two's complement). */
  public int readUInt32() throws IOException {
    fill(4);
    return buffer.getInt(0);
  }

  public long readInt64() throws IOException {
    fill(8);
    return buffer.getLong(0);
  }

  /** Returns the 8 bytes as a long (unsigned 64-bit value in two's complement). */
  public long readUInt64() throws IOException {
    fill(8);
    return buffer.getLong(0);
  }

  public int readInt32() throws IOException {
    fill(4);
    return buffer.getInt(0);
  }

  /** Returns the 2 bytes as a short (unsigned 16-bit value in two's complement). */
  public short readUInt16() throws IOException {
    fill(2);
    return buffer.getShort(0);
  }

  public byte[] readBytes(int length) throws IOException {
    ByteBuffer buf = ByteBuffer.wrap(new byte[length]);
    channel.read(buf);
    return buf.array();
  }

  public String readString(int length) throws IOException {
    ByteBuffer buf = ByteBuffer.wrap(new byte[length]);
    channel.read(buf);
    buf.position(0);
    return StandardCharsets.US_ASCII.decode(buf).toString();
  }

  // --- BE/LE overloads (formerly extension functions in ReadUtils.kt) ---

  public short readUInt16(boolean isBe) throws IOException {
    short value = readUInt16();
    return isBe ? Short.reverseBytes(value) : value;
  }

  public int readUInt32(boolean isBe) throws IOException {
    int value = readUInt32();
    return isBe ? Integer.reverseBytes(value) : value;
  }

  public long readUInt64(boolean isBe) throws IOException {
    long value = readUInt64();
    return isBe ? Long.reverseBytes(value) : value;
  }

  public short readUInt16Le(boolean isBe) throws IOException {
    short value = readUInt16();
    return isBe ? Short.reverseBytes(value) : value;
  }

  public int readUInt32Le(boolean isBe) throws IOException {
    int value = readUInt32();
    return isBe ? Integer.reverseBytes(value) : value;
  }

  public int readUInt32Be() throws IOException {
    return Integer.reverseBytes(readUInt32());
  }

  public long readUInt64Le(boolean isBe) throws IOException {
    long value = readUInt64();
    return isBe ? Long.reverseBytes(value) : value;
  }

  private void fill(int length) throws IOException {
    buffer.clear().limit(length);
    int read = channel.read(buffer);
    if (read <= 0) throw new EOFException();
    buffer.rewind();
  }
}
