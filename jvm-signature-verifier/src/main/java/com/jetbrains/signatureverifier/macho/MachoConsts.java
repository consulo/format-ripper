package com.jetbrains.signatureverifier.macho;

public final class MachoConsts {
  public static final long FAT_MAGIC = 0xCAFEBABEL;
  public static final long FAT_MAGIC_64 = 0xCAFEBABFL;
  public static final long FAT_CIGAM = 0xBEBAFECAL;
  public static final long FAT_CIGAM_64 = 0xBFBAFECAL;
  public static final long MH_MAGIC = 0xFEEDFACEL;
  public static final long MH_MAGIC_64 = 0xFEEDFACFL;
  public static final long MH_CIGAM = 0xCEFAEDFEL;
  public static final long MH_CIGAM_64 = 0xCFFAEDFEL;
  public static final int CSSLOT_CODEDIRECTORY = 0;       // slot index for CodeDirectory
  public static final int CSSLOT_CMS_SIGNATURE = 0x10000; // slot index for CmsSignedData
  public static final long CSMAGIC_BLOBWRAPPER = 0xfade0b01L;   // used for the cms blob
  public static final long CSMAGIC_CODEDIRECTORY = 0xfade0c02L; // used for the CodeDirectory blob
  public static final int LC_SEGMENT = 1;
  public static final int LC_SEGMENT_64 = 0x19;
  public static final int LC_CODE_SIGNATURE = 0x1D;

  private MachoConsts() {
  }
}
