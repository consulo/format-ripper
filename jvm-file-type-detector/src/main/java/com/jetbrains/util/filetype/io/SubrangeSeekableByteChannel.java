package com.jetbrains.util.filetype.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.NonWritableChannelException;
import java.nio.channels.SeekableByteChannel;

/**
 * A read-only SeekableByteChannel that exposes a subrange [startOffset, startOffset + length)
 * of an underlying base channel. The channel maintains its own independent position within
 * the subrange and does not close the base channel when closed.
 */
public class SubrangeSeekableByteChannel implements SeekableByteChannel {
  private final SeekableByteChannel base;
  private final long startOffset;
  private final long length;
  private long pos = 0;

  public SubrangeSeekableByteChannel(SeekableByteChannel base, long startOffset, long length) {
    if (startOffset < 0) throw new IllegalArgumentException("startOffset must be >= 0");
    if (length < 0) throw new IllegalArgumentException("length must be >= 0");
    this.base = base;
    this.startOffset = startOffset;
    this.length = length;
  }

  @Override
  public boolean isOpen() {
    return base.isOpen();
  }

  @Override
  public void close() {
    // no-op: do not close the base channel
  }

  @Override
  public int read(ByteBuffer dst) throws IOException {
    if (pos >= length) return -1;
    if (!dst.hasRemaining()) return 0;

    int allowed = (int) Math.min(length - pos, dst.remaining());

    int originalLimit = dst.limit();
    int limitedLimit = dst.position() + allowed;
    if (limitedLimit < originalLimit) {
      dst.limit(limitedLimit);
    }

    base.position(startOffset + pos);
    int read;
    try {
      read = base.read(dst);
    } finally {
      dst.limit(originalLimit);
    }

    if (read > 0) pos += read;
    return (read == 0 && allowed == 0) ? -1 : read;
  }

  @Override
  public int write(ByteBuffer src) {
    throw new NonWritableChannelException();
  }

  @Override
  public long position() {
    return pos;
  }

  @Override
  public SeekableByteChannel position(long newPosition) {
    if (newPosition < 0) throw new IllegalArgumentException("position must be >= 0");
    if (newPosition > length) throw new IllegalArgumentException("position must be <= length");
    pos = newPosition;
    return this;
  }

  @Override
  public long size() {
    return length;
  }

  @Override
  public SeekableByteChannel truncate(long size) {
    throw new NonWritableChannelException();
  }
}
