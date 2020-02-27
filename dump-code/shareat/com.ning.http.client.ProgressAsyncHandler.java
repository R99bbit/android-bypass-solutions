package com.ning.http.client;

import com.ning.http.client.AsyncHandler.STATE;

public interface ProgressAsyncHandler<T> extends AsyncHandler<T> {
    STATE onContentWriteCompleted();

    STATE onContentWriteProgress(long j, long j2, long j3);

    STATE onHeaderWriteCompleted();
}