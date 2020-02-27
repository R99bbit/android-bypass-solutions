package com.ning.http.client;

import java.io.IOException;

public interface ResumableBodyConsumer extends BodyConsumer {
    long getTransferredBytes() throws IOException;

    void resume() throws IOException;
}