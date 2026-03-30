package com.jetbrains.util.filetype.elf;

import org.jspecify.annotations.Nullable;

public class ElfInfo {
  private final ElfClass elfClass;
  private final ElfData data;
  private final ElfOsAbi osAbi;
  private final byte osAbiVersion;
  private final ElfType type;
  private final ElfMachine machine;
  private final long flags;
  private final @Nullable String interpreter;

  public ElfInfo(ElfClass elfClass, ElfData data, ElfOsAbi osAbi, byte osAbiVersion,
                 ElfType type, ElfMachine machine, long flags, @Nullable String interpreter) {
    this.elfClass = elfClass;
    this.data = data;
    this.osAbi = osAbi;
    this.osAbiVersion = osAbiVersion;
    this.type = type;
    this.machine = machine;
    this.flags = flags;
    this.interpreter = interpreter;
  }

  public ElfClass getElfClass() { return elfClass; }
  public ElfData getData() { return data; }
  public ElfOsAbi getOsAbi() { return osAbi; }
  public byte getOsAbiVersion() { return osAbiVersion; }
  public ElfType getType() { return type; }
  public ElfMachine getMachine() { return machine; }
  public long getFlags() { return flags; }
  public @Nullable String getInterpreter() { return interpreter; }

  // Kotlin-style accessors
  public ElfClass ElfClass() { return elfClass; }
  public ElfData Data() { return data; }
  public ElfOsAbi OsAbi() { return osAbi; }
  public byte OsAbiVersion() { return osAbiVersion; }
  public ElfType Type() { return type; }
  public ElfMachine Machine() { return machine; }
  public long Flags() { return flags; }
  public @Nullable String Interpreter() { return interpreter; }
}
