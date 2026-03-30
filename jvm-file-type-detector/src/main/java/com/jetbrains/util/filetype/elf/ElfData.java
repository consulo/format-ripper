package com.jetbrains.util.filetype.elf;

public enum ElfData {
  ELFDATANONE((byte) 0),
  ELFDATA2LSB((byte) 1),
  ELFDATA2MSB((byte) 2);

  public final byte v;

  ElfData(byte v) {
    this.v = v;
  }
}
