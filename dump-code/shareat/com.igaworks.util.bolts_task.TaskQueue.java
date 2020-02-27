package com.igaworks.util.bolts_task;

import java.util.Arrays;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

public class TaskQueue {
    private final Lock lock = new ReentrantLock();
    private Task<Void> tail;

    private Task<Void> getTaskToAwait() {
        this.lock.lock();
        try {
            return (this.tail != null ? this.tail : Task.forResult(null)).continueWith(new Continuation<Void, Void>() {
                public Void then(Task<Void> task) throws Exception {
                    return null;
                }
            });
        } finally {
            this.lock.unlock();
        }
    }

    /* access modifiers changed from: 0000 */
    public <T> Task<T> enqueue(Continuation<Void, Task<T>> taskStart) {
        this.lock.lock();
        try {
            Task<T> task = (Task) taskStart.then(getTaskToAwait());
            this.tail = Task.whenAll(Arrays.asList(new Task[]{this.tail != null ? this.tail : Task.forResult(null), task}));
            this.lock.unlock();
            return task;
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e2) {
            throw new RuntimeException(e2);
        } catch (Throwable th) {
            this.lock.unlock();
            throw th;
        }
    }

    static <T> Continuation<T, Task<T>> waitFor(final Task<Void> toAwait) {
        return new Continuation<T, Task<T>>() {
            public Task<T> then(final Task<T> task) throws Exception {
                return Task.this.continueWithTask(new Continuation<Void, Task<T>>() {
                    public Task<T> then(Task<Void> task) throws Exception {
                        return task;
                    }
                });
            }
        };
    }

    /* access modifiers changed from: 0000 */
    public Lock getLock() {
        return this.lock;
    }

    /* access modifiers changed from: 0000 */
    public void waitUntilFinished() throws InterruptedException {
        this.lock.lock();
        try {
            if (this.tail != null) {
                this.tail.waitForCompletion();
                this.lock.unlock();
            }
        } finally {
            this.lock.unlock();
        }
    }
}