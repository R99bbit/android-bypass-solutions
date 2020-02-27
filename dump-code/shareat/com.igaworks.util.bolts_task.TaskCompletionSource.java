package com.igaworks.util.bolts_task;

public class TaskCompletionSource<TResult> {
    private final Task<TResult> task = new Task<>();

    public Task<TResult> getTask() {
        return this.task;
    }

    public boolean trySetCancelled() {
        return this.task.trySetCancelled();
    }

    public boolean trySetResult(TResult result) {
        return this.task.trySetResult(result);
    }

    public boolean trySetError(Exception error) {
        return this.task.trySetError(error);
    }

    public void setCancelled() {
        if (!trySetCancelled()) {
            throw new IllegalStateException("Cannot cancel a completed task.");
        }
    }

    public void setResult(TResult result) {
        if (!trySetResult(result)) {
            throw new IllegalStateException("Cannot set the result of a completed task.");
        }
    }

    public void setError(Exception error) {
        if (!trySetError(error)) {
            throw new IllegalStateException("Cannot set the error on a completed task.");
        }
    }
}