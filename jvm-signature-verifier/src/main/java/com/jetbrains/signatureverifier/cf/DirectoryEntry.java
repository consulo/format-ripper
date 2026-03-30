package com.jetbrains.signatureverifier.cf;

import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;

public class DirectoryEntry {
  public final byte[] name;
  public final byte entryType;
  public final byte[] clsid;
  public final int startSect;
  public final int sizeLow;
  public final int sizeHigh;

  public DirectoryEntry(SeekableByteChannel stream, BinaryReader reader) throws IOException {
    byte[] _name = reader.readBytes(64);
    short _nameLen = reader.readUInt16();

    if ((_nameLen & 0xFFFF) > 2) {
      int len = (_nameLen & 0xFFFF) - 2;
      name = new byte[len];
      System.arraycopy(_name, 0, name, 0, len);
    } else {
      name = new byte[0];
    }

    entryType = reader.readByte();

    if (entryType == DirectoryEntryType.STGTY_ROOT) {
      ReadUtils.skip(stream, 13);
      clsid = reader.readBytes(16);
      ReadUtils.skip(stream, 20);
    } else {
      clsid = null;
      ReadUtils.skip(stream, 49);
    }

    startSect = reader.readUInt32();
    sizeLow = reader.readUInt32();
    sizeHigh = reader.readUInt32();
  }
}
