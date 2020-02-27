package com.ning.http.client;

import java.io.IOException;

public interface BodyGenerator {
    Body createBody() throws IOException;
}