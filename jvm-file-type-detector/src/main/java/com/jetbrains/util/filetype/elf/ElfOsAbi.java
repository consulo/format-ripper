package com.jetbrains.util.filetype.elf;

public enum ElfOsAbi {
  ELFOSABI_NONE((byte) 0),
  ELFOSABI_HPUX((byte) 1),
  ELFOSABI_NETBSD((byte) 2),
  ELFOSABI_LINUX((byte) 3),
  ELFOSABI_HURD((byte) 4),
  ELFOSABI_86OPEN((byte) 5),
  ELFOSABI_SOLARIS((byte) 6),
  ELFOSABI_AIX((byte) 7),
  ELFOSABI_IRIX((byte) 8),
  ELFOSABI_FREEBSD((byte) 9),
  ELFOSABI_TRU64((byte) 10),
  ELFOSABI_MODESTO((byte) 11),
  ELFOSABI_OPENBSD((byte) 12),
  ELFOSABI_OPENVMS((byte) 13),
  ELFOSABI_NSK((byte) 14),
  ELFOSABI_AROS((byte) 15),
  ELFOSABI_FENIXOS((byte) 16),
  ELFOSABI_CLOUDABI((byte) 17),
  ELFOSABI_OPENVOS((byte) 18);

  public final byte v;

  ElfOsAbi(byte v) {
    this.v = v;
  }

  public static ElfOsAbi fromValue(byte v) {
    for (ElfOsAbi e : values()) {
      if (e.v == v) return e;
    }
    throw new IllegalArgumentException("Unknown ElfOsAbi value: " + v);
  }
}
