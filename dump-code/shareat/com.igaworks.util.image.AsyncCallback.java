package com.igaworks.util.image;

public interface AsyncCallback<T> {
    void cancelled();

    void exceptionOccured(Exception exc);

    void onResult(T t);
}