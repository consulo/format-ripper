package com.jetbrains.util.filetype;

public enum FileType {
  Unknown(0),
  Pe(1),
  Msi(2),
  MachO(3),
  Elf(4),
  ShebangScript(5);

  private final int value;

  FileType(int value) {
    this.value = value;
  }
}
