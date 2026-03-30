package com.jetbrains.signatureverifier.cf;

public final class SpecialSectors {
  /** Specifies a DIFAT sector in the FAT */
  public static final long DIFSECT = 0xFFFFFFFCL;

  /** Specifies a FAT sector in the FAT */
  public static final long FATSECT = 0xFFFFFFFDL;

  /** End of a linked chain of sectors */
  public static final long ENDOFCHAIN = 0xFFFFFFFEL;

  /** Specifies an unallocated sector in the FAT, Mini FAT, or DIFAT */
  public static final long FREESECT = 0xFFFFFFFFL;

  private SpecialSectors() {
  }
}
