package com.jetbrains.signatureverifier.macho;

import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;
import com.jetbrains.util.filetype.io.SeekOrigin;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;

// Note: See https://opensource.apple.com/source/xnu/xnu-344/EXTERNAL_HEADERS/mach-o/fat.h
// Note: See https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/loader.h
public class MachoUtils {
  public static boolean isFatMacho(long magic) {
    return magic == MachoConsts.FAT_MAGIC || magic == MachoConsts.FAT_MAGIC_64
      || magic == MachoConsts.FAT_CIGAM || magic == MachoConsts.FAT_CIGAM_64;
  }

  public static boolean isMacho(long magic) {
    return magic == MachoConsts.MH_MAGIC || magic == MachoConsts.MH_MAGIC_64
      || magic == MachoConsts.MH_CIGAM || magic == MachoConsts.MH_CIGAM_64;
  }

  public static byte[] ReadBlob(BinaryReader reader) throws IOException {
    reader.readUInt32Le(true); // magic
    int length = reader.readUInt32Le(true);
    return reader.readBytes(length);
  }

  public static byte[] ReadCodeDirectoryBlob(BinaryReader reader) throws IOException {
    reader.readUInt32Le(true); // magic
    int length = reader.readUInt32Le(true);
    ReadUtils.seek((SeekableByteChannel) reader.getBaseStream(), -8, SeekOrigin.Current);
    return reader.readBytes(length);
  }
}
