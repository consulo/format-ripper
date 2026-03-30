package com.jetbrains.util.filetype.elf;

public enum ElfClass {
  ELFCLASSNONE((byte) 0),
  ELFCLASS32((byte) 1),
  ELFCLASS64((byte) 2);

  public final byte v;

  ElfClass(byte v) {
    this.v = v;
  }
}
