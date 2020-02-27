package org.slf4j.helpers;

import org.slf4j.Logger;
import org.slf4j.Marker;

public abstract class MarkerIgnoringBase extends NamedLoggerBase implements Logger {
    private static final long serialVersionUID = 9044267456635152283L;

    public /* bridge */ /* synthetic */ String getName() {
        return super.getName();
    }

    public boolean isTraceEnabled(Marker marker) {
        return isTraceEnabled();
    }

    public void trace(Marker marker, String msg) {
        trace(msg);
    }

    public void trace(Marker marker, String format, Object arg) {
        trace(format, arg);
    }

    public void trace(Marker marker, String format, Object arg1, Object arg2) {
        trace(format, arg1, arg2);
    }

    public void trace(Marker marker, String format, Object... arguments) {
        trace(format, arguments);
    }

    public void trace(Marker marker, String msg, Throwable t) {
        trace(msg, t);
    }

    public boolean isDebugEnabled(Marker marker) {
        return isDebugEnabled();
    }

    public void debug(Marker marker, String msg) {
        debug(msg);
    }

    public void debug(Marker marker, String format, Object arg) {
        debug(format, arg);
    }

    public void debug(Marker marker, String format, Object arg1, Object arg2) {
        debug(format, arg1, arg2);
    }

    public void debug(Marker marker, String format, Object... arguments) {
        debug(format, arguments);
    }

    public void debug(Marker marker, String msg, Throwable t) {
        debug(msg, t);
    }

    public boolean isInfoEnabled(Marker marker) {
        return isInfoEnabled();
    }

    public void info(Marker marker, String msg) {
        info(msg);
    }

    public void info(Marker marker, String format, Object arg) {
        info(format, arg);
    }

    public void info(Marker marker, String format, Object arg1, Object arg2) {
        info(format, arg1, arg2);
    }

    public void info(Marker marker, String format, Object... arguments) {
        info(format, arguments);
    }

    public void info(Marker marker, String msg, Throwable t) {
        info(msg, t);
    }

    public boolean isWarnEnabled(Marker marker) {
        return isWarnEnabled();
    }

    public void warn(Marker marker, String msg) {
        warn(msg);
    }

    public void warn(Marker marker, String format, Object arg) {
        warn(format, arg);
    }

    public void warn(Marker marker, String format, Object arg1, Object arg2) {
        warn(format, arg1, arg2);
    }

    public void warn(Marker marker, String format, Object... arguments) {
        warn(format, arguments);
    }

    public void warn(Marker marker, String msg, Throwable t) {
        warn(msg, t);
    }

    public boolean isErrorEnabled(Marker marker) {
        return isErrorEnabled();
    }

    public void error(Marker marker, String msg) {
        error(msg);
    }

    public void error(Marker marker, String format, Object arg) {
        error(format, arg);
    }

    public void error(Marker marker, String format, Object arg1, Object arg2) {
        error(format, arg1, arg2);
    }

    public void error(Marker marker, String format, Object... arguments) {
        error(format, arguments);
    }

    public void error(Marker marker, String msg, Throwable t) {
        error(msg, t);
    }

    public String toString() {
        return getClass().getName() + "(" + getName() + ")";
    }
}