package com.fasterxml.jackson.databind.deser.impl;

import java.io.IOException;

public class ReadableObjectId {
    public final Object id;
    public Object item;

    public ReadableObjectId(Object obj) {
        this.id = obj;
    }

    public void bindItem(Object obj) throws IOException {
        if (this.item != null) {
            throw new IllegalStateException("Already had POJO for id (" + this.id.getClass().getName() + ") [" + this.id + "]");
        }
        this.item = obj;
    }
}