package com.igaworks.util.image;

import android.os.AsyncTask;
import java.util.concurrent.Callable;

public class AsyncExecutor<T> extends AsyncTask<Void, Void, T> {
    private static final String TAG = "AsyncExecutor";
    private Callable<T> callable;
    private AsyncCallback<T> callback;
    private Exception occuredException;

    public AsyncExecutor<T> setCallable(Callable<T> callable2) {
        this.callable = callable2;
        return this;
    }

    public AsyncExecutor<T> setCallback(AsyncCallback<T> callback2) {
        this.callback = callback2;
        processAsyncExecutorAware(callback2);
        return this;
    }

    private void processAsyncExecutorAware(AsyncCallback<T> callback2) {
        if (callback2 instanceof AsyncExecutorAware) {
            ((AsyncExecutorAware) callback2).setAsyncExecutor(this);
        }
    }

    /* access modifiers changed from: protected */
    public T doInBackground(Void... params) {
        try {
            return this.callable.call();
        } catch (Exception ex) {
            this.occuredException = ex;
            return null;
        }
    }

    /* access modifiers changed from: protected */
    public void onPostExecute(T result) {
        try {
            if (isCancelled()) {
                notifyCanceled();
            }
            if (isExceptionOccured()) {
                notifyException();
            } else {
                notifyResult(result);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void notifyCanceled() {
        if (this.callback != null) {
            this.callback.cancelled();
        }
    }

    private boolean isExceptionOccured() {
        return this.occuredException != null;
    }

    private void notifyException() {
        if (this.callback != null) {
            this.callback.exceptionOccured(this.occuredException);
        }
    }

    private void notifyResult(T result) {
        if (this.callback != null) {
            this.callback.onResult(result);
        }
    }
}