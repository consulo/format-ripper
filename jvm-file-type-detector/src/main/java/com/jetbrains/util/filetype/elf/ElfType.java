package com.jetbrains.util.filetype.elf;

public enum ElfType {
  ET_NONE(0),
  ET_REL(1),
  ET_EXEC(2),
  ET_DYN(3),
  ET_CORE(4),
  ET_LOOS(0xfe00),
  ET_HIOS(0xfeff),
  ET_LOPROC(0xff00),
  ET_HIPROC(0xffff);

  public final int v;

  ElfType(int v) {
    this.v = v;
  }

  public static ElfType fromValue(int v) {
    for (ElfType e : values()) {
      if (e.v == v) return e;
    }
    throw new IllegalArgumentException("Unknown ElfType value: " + v);
  }
}
