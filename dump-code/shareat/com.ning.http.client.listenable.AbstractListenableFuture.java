package com.ning.http.client.listenable;

import com.ning.http.client.ListenableFuture;
import java.util.concurrent.Executor;

public abstract class AbstractListenableFuture<V> implements ListenableFuture<V> {
    private final ExecutionList executionList = new ExecutionList();

    public ListenableFuture<V> addListener(Runnable listener, Executor exec) {
        this.executionList.add(listener, exec);
        return this;
    }

    /* access modifiers changed from: protected */
    public void runListeners() {
        this.executionList.run();
    }
}