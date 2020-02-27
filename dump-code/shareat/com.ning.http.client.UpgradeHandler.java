package com.ning.http.client;

public interface UpgradeHandler<T> {
    void onFailure(Throwable th);

    void onSuccess(T t);
}