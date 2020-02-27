package org.jboss.netty.util.internal;

public class ThreadLocalBoolean extends ThreadLocal<Boolean> {
    private final boolean defaultValue;

    public ThreadLocalBoolean() {
        this(false);
    }

    public ThreadLocalBoolean(boolean defaultValue2) {
        this.defaultValue = defaultValue2;
    }

    /* access modifiers changed from: protected */
    public Boolean initialValue() {
        return this.defaultValue ? Boolean.TRUE : Boolean.FALSE;
    }
}