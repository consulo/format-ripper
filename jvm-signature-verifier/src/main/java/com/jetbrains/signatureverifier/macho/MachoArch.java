package com.jetbrains.signatureverifier.macho;

import com.jetbrains.signatureverifier.DataInfo;
import com.jetbrains.signatureverifier.InvalidDataException;
import com.jetbrains.util.filetype.io.BinaryReader;
import com.jetbrains.util.filetype.io.ReadUtils;
import com.jetbrains.util.filetype.io.SeekOrigin;
import com.jetbrains.util.filetype.io.SubrangeSeekableByteChannel;

import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Fat/Universal Mach-O file
 */
public class MachoArch {
  private final SeekableByteChannel stream;

  /**
   * Initializes a new instance of the MachoArch
   *
   * @param stream An input stream
   */
  public MachoArch(SeekableByteChannel stream) {
    this.stream = stream;
  }

  /**
   * Return a list of macho architectures from fat-macho or one-item list for macho
   *
   * @return A collection of MachoFile
   */
  public Collection<MachoFile> extract() throws IOException {
    BinaryReader reader = new BinaryReader(ReadUtils.rewind(stream));
    long masterMagic = Integer.toUnsignedLong(reader.readUInt32()); // mach_header::magic / mach_header64::magic / fat_header::magic
    if (MachoUtils.isMacho(masterMagic))
      return Collections.singletonList(getMachoData(ReadUtils.rewind(stream)));
    else if (MachoUtils.isFatMacho(masterMagic))
      return getFatMachoData(reader, masterMagic);
    else
      throw new InvalidDataException("Unknown format");
  }

  private Collection<MachoFile> getFatMachoData(BinaryReader reader, long magic) throws IOException {
    boolean isLe32 = magic == MachoConsts.FAT_MAGIC;
    boolean isLe64 = magic == MachoConsts.FAT_MAGIC_64;
    boolean isBe32 = magic == MachoConsts.FAT_CIGAM;
    boolean isBe64 = magic == MachoConsts.FAT_CIGAM_64;

    if (isLe32 || isLe64 || isBe32 || isBe64) {
      boolean isBe = isBe32 || isBe64;
      int nFatArch = reader.readUInt32Le(isBe); // fat_header::nfat_arch
      List<DataInfo> fatArchItems = new ArrayList<>();

      if (isBe64 || isLe64) {
        int n = nFatArch;
        while (n-- > 0) {
          ReadUtils.seek(stream, 8, SeekOrigin.Current);
          int offset = (int) reader.readUInt64Le(isBe64); // fat_arch_64::offset
          int size = (int) reader.readUInt64Le(isBe64);   // fat_arch_64::size
          fatArchItems.add(new DataInfo(offset, size));
          ReadUtils.seek(stream, 8, SeekOrigin.Current);
        }
      } else {
        int n = nFatArch;
        while (n-- > 0) {
          ReadUtils.seek(stream, 8, SeekOrigin.Current);
          int offset = reader.readUInt32Le(isBe32); // fat_arch::offset
          int size = reader.readUInt32Le(isBe32);   // fat_arch::size
          fatArchItems.add(new DataInfo(offset, size));
          ReadUtils.seek(stream, 4, SeekOrigin.Current);
        }
      }

      List<MachoFile> result = new ArrayList<>();
      for (DataInfo s : fatArchItems) {
        // Create a subrange channel over the original stream without copying data
        result.add(new MachoFile(new SubrangeSeekableByteChannel(stream, (long) s.getOffset(), (long) s.getSize())));
      }
      return result;
    }
    throw new InvalidDataException("Unknown format");
  }

  private MachoFile getMachoData(SeekableByteChannel stream) {
    return new MachoFile(stream);
  }
}
