package com.igaworks.adbrix.model;

public class Segment<T> {
    private String key;
    private String op;
    private String scheme;
    private T val;

    public Segment() {
    }

    public Segment(String scheme2, String key2, String op2, T val2) {
        this.scheme = scheme2;
        this.key = key2;
        this.op = op2;
        this.val = val2;
    }

    public String getScheme() {
        return this.scheme;
    }

    public void setScheme(String scheme2) {
        this.scheme = scheme2;
    }

    public String getKey() {
        return this.key;
    }

    public void setKey(String key2) {
        this.key = key2;
    }

    public String getOp() {
        return this.op;
    }

    public void setOp(String op2) {
        this.op = op2;
    }

    public T getVal() {
        return this.val;
    }

    public void setVal(T val2) {
        this.val = val2;
    }
}