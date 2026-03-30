package com.jetbrains.util.filetype.io;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;

/**
 * Static utility methods for SeekableByteChannel (ported from Kotlin extension functions).
 */
public final class ReadUtils {

  public static SeekableByteChannel rewind(SeekableByteChannel channel) throws IOException {
    channel.position(0);
    return channel;
  }

  public static void skip(SeekableByteChannel channel, long len) throws IOException {
    seek(channel, len, SeekOrigin.Current);
  }

  public static void jump(SeekableByteChannel channel, long position) throws IOException {
    seek(channel, position, SeekOrigin.Begin);
  }

  public static void seek(SeekableByteChannel channel, long position, SeekOrigin origin) throws IOException {
    switch (origin) {
      case Begin:
        channel.position(position);
        break;
      case Current:
        channel.position(channel.position() + position);
        break;
      case End:
        channel.position(channel.size() + position);
        break;
    }
  }

  public static byte[] readAll(SeekableByteChannel channel) throws IOException {
    rewind(channel);
    ByteBuffer buf = ByteBuffer.wrap(new byte[(int) channel.size()]);
    channel.read(buf);
    return buf.array();
  }

  public static byte[] readToEnd(SeekableByteChannel channel) throws IOException {
    long pos = channel.position();
    long size = channel.size();
    if (pos >= size) return new byte[0];
    ByteBuffer buf = ByteBuffer.wrap(new byte[(int) (size - pos)]);
    channel.read(buf);
    return buf.array();
  }

  private ReadUtils() {
  }
}
