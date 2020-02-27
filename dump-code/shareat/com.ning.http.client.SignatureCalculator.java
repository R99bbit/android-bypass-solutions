package com.ning.http.client;

public interface SignatureCalculator {
    void calculateAndAddSignature(String str, Request request, RequestBuilderBase<?> requestBuilderBase);
}