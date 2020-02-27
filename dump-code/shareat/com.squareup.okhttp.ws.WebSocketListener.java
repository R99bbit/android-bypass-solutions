package com.squareup.okhttp.ws;

import com.squareup.okhttp.Response;
import com.squareup.okhttp.ws.WebSocket.PayloadType;
import java.io.IOException;
import okio.Buffer;
import okio.BufferedSource;

public interface WebSocketListener {
    void onClose(int i, String str);

    void onFailure(IOException iOException, Response response);

    void onMessage(BufferedSource bufferedSource, PayloadType payloadType) throws IOException;

    void onOpen(WebSocket webSocket, Response response);

    void onPong(Buffer buffer);
}