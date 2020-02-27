package org.slf4j.helpers;

public class NOPLogger extends MarkerIgnoringBase {
    public static final NOPLogger NOP_LOGGER = new NOPLogger();
    private static final long serialVersionUID = -517220405410904473L;

    protected NOPLogger() {
    }

    public String getName() {
        return "NOP";
    }

    public final boolean isTraceEnabled() {
        return false;
    }

    public final void trace(String msg) {
    }

    public final void trace(String format, Object arg) {
    }

    public final void trace(String format, Object arg1, Object arg2) {
    }

    public final void trace(String format, Object... argArray) {
    }

    public final void trace(String msg, Throwable t) {
    }

    public final boolean isDebugEnabled() {
        return false;
    }

    public final void debug(String msg) {
    }

    public final void debug(String format, Object arg) {
    }

    public final void debug(String format, Object arg1, Object arg2) {
    }

    public final void debug(String format, Object... argArray) {
    }

    public final void debug(String msg, Throwable t) {
    }

    public final boolean isInfoEnabled() {
        return false;
    }

    public final void info(String msg) {
    }

    public final void info(String format, Object arg1) {
    }

    public final void info(String format, Object arg1, Object arg2) {
    }

    public final void info(String format, Object... argArray) {
    }

    public final void info(String msg, Throwable t) {
    }

    public final boolean isWarnEnabled() {
        return false;
    }

    public final void warn(String msg) {
    }

    public final void warn(String format, Object arg1) {
    }

    public final void warn(String format, Object arg1, Object arg2) {
    }

    public final void warn(String format, Object... argArray) {
    }

    public final void warn(String msg, Throwable t) {
    }

    public final boolean isErrorEnabled() {
        return false;
    }

    public final void error(String msg) {
    }

    public final void error(String format, Object arg1) {
    }

    public final void error(String format, Object arg1, Object arg2) {
    }

    public final void error(String format, Object... argArray) {
    }

    public final void error(String msg, Throwable t) {
    }
}