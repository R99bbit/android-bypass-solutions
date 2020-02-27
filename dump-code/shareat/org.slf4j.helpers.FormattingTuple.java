package org.slf4j.helpers;

public class FormattingTuple {
    public static FormattingTuple NULL = new FormattingTuple(null);
    private Object[] argArray;
    private String message;
    private Throwable throwable;

    public FormattingTuple(String message2) {
        this(message2, null, null);
    }

    public FormattingTuple(String message2, Object[] argArray2, Throwable throwable2) {
        this.message = message2;
        this.throwable = throwable2;
        if (throwable2 == null) {
            this.argArray = argArray2;
        } else {
            this.argArray = trimmedCopy(argArray2);
        }
    }

    static Object[] trimmedCopy(Object[] argArray2) {
        if (argArray2 == null || argArray2.length == 0) {
            throw new IllegalStateException("non-sensical empty or null argument array");
        }
        int trimemdLen = argArray2.length - 1;
        Object[] trimmed = new Object[trimemdLen];
        System.arraycopy(argArray2, 0, trimmed, 0, trimemdLen);
        return trimmed;
    }

    public String getMessage() {
        return this.message;
    }

    public Object[] getArgArray() {
        return this.argArray;
    }

    public Throwable getThrowable() {
        return this.throwable;
    }
}