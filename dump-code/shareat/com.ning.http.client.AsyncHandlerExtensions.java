package com.ning.http.client;

public interface AsyncHandlerExtensions {
    void onRequestSent();

    void onRetry();
}