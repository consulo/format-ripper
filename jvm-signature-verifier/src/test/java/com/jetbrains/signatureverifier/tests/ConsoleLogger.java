package com.jetbrains.signatureverifier.tests;

import com.jetbrains.signatureverifier.ILogger;

public class ConsoleLogger implements ILogger {
  public static final ConsoleLogger Instance = new ConsoleLogger();

  @Override
  public void Info(String str) { System.out.println("INFO: " + str); }

  @Override
  public void Warning(String str) { System.out.println("WARNING: " + str); }

  @Override
  public void Error(String str) { System.out.println("ERROR: " + str); }

  @Override
  public void Trace(String str) { System.out.println("TRACE: " + str); }
}
