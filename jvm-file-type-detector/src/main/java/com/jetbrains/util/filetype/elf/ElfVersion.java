package com.jetbrains.util.filetype.elf;

public enum ElfVersion {
  EV_NONE((byte) 0),
  EV_CURRENT((byte) 1);

  public final byte v;

  ElfVersion(byte v) {
    this.v = v;
  }

  public static ElfVersion fromValue(byte v) {
    for (ElfVersion e : values()) {
      if (e.v == v) return e;
    }
    throw new IllegalArgumentException("Unknown ElfVersion value: " + v);
  }
}
