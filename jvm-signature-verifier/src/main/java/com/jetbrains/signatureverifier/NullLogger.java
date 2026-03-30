package com.jetbrains.signatureverifier;

public class NullLogger implements ILogger {
  public static final NullLogger Instance = new NullLogger();

  @Override
  public void Info(String str) {
  }

  @Override
  public void Warning(String str) {
  }

  @Override
  public void Error(String str) {
  }

  @Override
  public void Trace(String str) {
  }
}
