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

  // Keep Kotlin-style property name for compatibility
  public ByteChannel BaseStream() {
    return channel;
  }

  public byte ReadByte() throws IOException {
    fill(1);
    return buffer.get(0);
  }

  /** Returns the 4 bytes as an int (unsigned 32-bit value in two's complement). */
  public int ReadUInt32() throws IOException {
    fill(4);
    return buffer.getInt(0);
  }

  public long ReadInt64() throws IOException {
    fill(8);
    return buffer.getLong(0);
  }

  /** Returns the 8 bytes as a long (unsigned 64-bit value in two's complement). */
  public long ReadUInt64() throws IOException {
    fill(8);
    return buffer.getLong(0);
  }

  public int ReadInt32() throws IOException {
    fill(4);
    return buffer.getInt(0);
  }

  /** Returns the 2 bytes as a short (unsigned 16-bit value in two's complement). */
  public short ReadUInt16() throws IOException {
    fill(2);
    return buffer.getShort(0);
  }

  public byte[] ReadBytes(int length) throws IOException {
    ByteBuffer buf = ByteBuffer.wrap(new byte[length]);
    channel.read(buf);
    return buf.array();
  }

  public String ReadString(int length) throws IOException {
    ByteBuffer buf = ByteBuffer.wrap(new byte[length]);
    channel.read(buf);
    buf.position(0);
    return StandardCharsets.US_ASCII.decode(buf).toString();
  }

  // --- BE/LE overloads (formerly extension functions in ReadUtils.kt) ---

  public short ReadUInt16(boolean isBe) throws IOException {
    short value = ReadUInt16();
    return isBe ? Short.reverseBytes(value) : value;
  }

  public int ReadUInt32(boolean isBe) throws IOException {
    int value = ReadUInt32();
    return isBe ? Integer.reverseBytes(value) : value;
  }

  public long ReadUInt64(boolean isBe) throws IOException {
    long value = ReadUInt64();
    return isBe ? Long.reverseBytes(value) : value;
  }

  public short ReadUInt16Le(boolean isBe) throws IOException {
    short value = ReadUInt16();
    return isBe ? Short.reverseBytes(value) : value;
  }

  public int ReadUInt32Le(boolean isBe) throws IOException {
    int value = ReadUInt32();
    return isBe ? Integer.reverseBytes(value) : value;
  }

  public int ReadUInt32Be() throws IOException {
    return Integer.reverseBytes(ReadUInt32());
  }

  public long ReadUInt64Le(boolean isBe) throws IOException {
    long value = ReadUInt64();
    return isBe ? Long.reverseBytes(value) : value;
  }

  private void fill(int length) throws IOException {
    buffer.clear().limit(length);
    int read = channel.read(buffer);
    if (read <= 0) throw new EOFException();
    buffer.rewind();
  }
}
