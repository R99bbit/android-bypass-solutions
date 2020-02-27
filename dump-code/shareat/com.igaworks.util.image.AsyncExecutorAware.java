package com.igaworks.util.image;

public interface AsyncExecutorAware<T> {
    void setAsyncExecutor(AsyncExecutor<T> asyncExecutor);
}