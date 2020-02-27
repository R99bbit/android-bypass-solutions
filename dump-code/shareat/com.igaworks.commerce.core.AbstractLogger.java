package com.igaworks.commerce.core;

public abstract class AbstractLogger {
    public static int DEBUG = 2;
    public static int ERROR = 3;
    public static int INFO = 1;
    protected int level;
    protected AbstractLogger nextLogger;

    /* access modifiers changed from: protected */
    public abstract void write(String str);

    public void setNextLogger(AbstractLogger nextLogger2) {
        this.nextLogger = nextLogger2;
    }

    public void logMessage(int level2, String message) {
        if (this.level <= level2) {
            write(message);
        }
        if (this.nextLogger != null) {
            this.nextLogger.logMessage(level2, message);
        }
    }
}