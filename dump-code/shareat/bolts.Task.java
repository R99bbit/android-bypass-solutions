package bolts;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class Task<TResult> {
    public static final ExecutorService BACKGROUND_EXECUTOR = BoltsExecutors.background();
    private static final Executor IMMEDIATE_EXECUTOR = BoltsExecutors.immediate();
    public static final Executor UI_THREAD_EXECUTOR = AndroidExecutors.uiThread();
    /* access modifiers changed from: private */
    public boolean cancelled;
    /* access modifiers changed from: private */
    public boolean complete;
    private List<Continuation<TResult, Void>> continuations = new ArrayList();
    /* access modifiers changed from: private */
    public Exception error;
    /* access modifiers changed from: private */
    public final Object lock = new Object();
    /* access modifiers changed from: private */
    public TResult result;

    public class TaskCompletionSource {
        private TaskCompletionSource() {
        }

        public Task<TResult> getTask() {
            return Task.this;
        }

        public boolean trySetCancelled() {
            boolean z = true;
            synchronized (Task.this.lock) {
                if (Task.this.complete) {
                    z = false;
                } else {
                    Task.this.complete = true;
                    Task.this.cancelled = true;
                    Task.this.lock.notifyAll();
                    Task.this.runContinuations();
                }
            }
            return z;
        }

        public boolean trySetResult(TResult result) {
            boolean z = true;
            synchronized (Task.this.lock) {
                if (Task.this.complete) {
                    z = false;
                } else {
                    Task.this.complete = true;
                    Task.this.result = result;
                    Task.this.lock.notifyAll();
                    Task.this.runContinuations();
                }
            }
            return z;
        }

        public boolean trySetError(Exception error) {
            boolean z = true;
            synchronized (Task.this.lock) {
                if (Task.this.complete) {
                    z = false;
                } else {
                    Task.this.complete = true;
                    Task.this.error = error;
                    Task.this.lock.notifyAll();
                    Task.this.runContinuations();
                }
            }
            return z;
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

    private Task() {
    }

    public static <TResult> TaskCompletionSource create() {
        Task<TResult> task = new Task<>();
        task.getClass();
        return new TaskCompletionSource<>();
    }

    public boolean isCompleted() {
        boolean z;
        synchronized (this.lock) {
            z = this.complete;
        }
        return z;
    }

    public boolean isCancelled() {
        boolean z;
        synchronized (this.lock) {
            z = this.cancelled;
        }
        return z;
    }

    public boolean isFaulted() {
        boolean z;
        synchronized (this.lock) {
            z = this.error != null;
        }
        return z;
    }

    public TResult getResult() {
        TResult tresult;
        synchronized (this.lock) {
            try {
                tresult = this.result;
            }
        }
        return tresult;
    }

    public Exception getError() {
        Exception exc;
        synchronized (this.lock) {
            exc = this.error;
        }
        return exc;
    }

    public void waitForCompletion() throws InterruptedException {
        synchronized (this.lock) {
            if (!isCompleted()) {
                this.lock.wait();
            }
        }
    }

    public static <TResult> Task<TResult> forResult(TResult value) {
        TaskCompletionSource tcs = create();
        tcs.setResult(value);
        return tcs.getTask();
    }

    public static <TResult> Task<TResult> forError(Exception error2) {
        TaskCompletionSource tcs = create();
        tcs.setError(error2);
        return tcs.getTask();
    }

    public static <TResult> Task<TResult> cancelled() {
        TaskCompletionSource tcs = create();
        tcs.setCancelled();
        return tcs.getTask();
    }

    public static Task<Void> delay(long delay) {
        return delay(delay, BoltsExecutors.scheduled());
    }

    static Task<Void> delay(long delay, ScheduledExecutorService executor) {
        if (delay <= 0) {
            return forResult(null);
        }
        final TaskCompletionSource create = create();
        executor.schedule(new Runnable() {
            public void run() {
                create.setResult(null);
            }
        }, delay, TimeUnit.MILLISECONDS);
        return create.getTask();
    }

    public <TOut> Task<TOut> cast() {
        return this;
    }

    public Task<Void> makeVoid() {
        return continueWithTask(new Continuation<TResult, Task<Void>>() {
            public Task<Void> then(Task<TResult> task) throws Exception {
                if (task.isCancelled()) {
                    return Task.cancelled();
                }
                if (task.isFaulted()) {
                    return Task.forError(task.getError());
                }
                return Task.forResult(null);
            }
        });
    }

    public static <TResult> Task<TResult> callInBackground(Callable<TResult> callable) {
        return call(callable, BACKGROUND_EXECUTOR, null);
    }

    public static <TResult> Task<TResult> callInBackground(Callable<TResult> callable, CancellationToken ct) {
        return call(callable, BACKGROUND_EXECUTOR, ct);
    }

    public static <TResult> Task<TResult> call(Callable<TResult> callable, Executor executor) {
        return call(callable, executor, null);
    }

    public static <TResult> Task<TResult> call(final Callable<TResult> callable, Executor executor, final CancellationToken ct) {
        final TaskCompletionSource tcs = create();
        executor.execute(new Runnable() {
            public void run() {
                if (ct == null || !ct.isCancellationRequested()) {
                    try {
                        tcs.setResult(callable.call());
                    } catch (CancellationException e) {
                        tcs.setCancelled();
                    } catch (Exception e2) {
                        tcs.setError(e2);
                    }
                } else {
                    tcs.setCancelled();
                }
            }
        });
        return tcs.getTask();
    }

    public static <TResult> Task<TResult> call(Callable<TResult> callable) {
        return call(callable, IMMEDIATE_EXECUTOR, null);
    }

    public static <TResult> Task<TResult> call(Callable<TResult> callable, CancellationToken ct) {
        return call(callable, IMMEDIATE_EXECUTOR, ct);
    }

    public static <TResult> Task<Task<TResult>> whenAnyResult(Collection<? extends Task<TResult>> tasks) {
        if (tasks.size() == 0) {
            return forResult(null);
        }
        final TaskCompletionSource create = create();
        final AtomicBoolean isAnyTaskComplete = new AtomicBoolean(false);
        for (Task<TResult> task : tasks) {
            task.continueWith(new Continuation<TResult, Void>() {
                public Void then(Task<TResult> task) {
                    if (isAnyTaskComplete.compareAndSet(false, true)) {
                        create.setResult(task);
                    }
                    return null;
                }
            });
        }
        return create.getTask();
    }

    public static Task<Task<?>> whenAny(Collection<? extends Task<?>> tasks) {
        if (tasks.size() == 0) {
            return forResult(null);
        }
        final TaskCompletionSource create = create();
        final AtomicBoolean isAnyTaskComplete = new AtomicBoolean(false);
        for (Task<?> task : tasks) {
            task.continueWith(new Continuation<Object, Void>() {
                public Void then(Task<Object> task) {
                    if (isAnyTaskComplete.compareAndSet(false, true)) {
                        create.setResult(task);
                    }
                    return null;
                }
            });
        }
        return create.getTask();
    }

    /* JADX WARNING: type inference failed for: r2v0, types: [java.util.Collection<? extends bolts.Task<TResult>>, java.util.Collection] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public static <TResult> Task<List<TResult>> whenAllResult(final Collection<? extends Task<TResult>> r2) {
        return whenAll(r2).onSuccess(new Continuation<Void, List<TResult>>() {
            public List<TResult> then(Task<Void> task) throws Exception {
                if (r2.size() == 0) {
                    return Collections.emptyList();
                }
                List<TResult> results = new ArrayList<>();
                for (Task<TResult> individualTask : r2) {
                    results.add(individualTask.getResult());
                }
                return results;
            }
        });
    }

    public static Task<Void> whenAll(Collection<? extends Task<?>> tasks) {
        if (tasks.size() == 0) {
            return forResult(null);
        }
        final TaskCompletionSource create = create();
        final ArrayList<Exception> causes = new ArrayList<>();
        final Object errorLock = new Object();
        final AtomicInteger count = new AtomicInteger(tasks.size());
        final AtomicBoolean isCancelled = new AtomicBoolean(false);
        for (Task<?> task : tasks) {
            task.continueWith(new Continuation<Object, Void>() {
                public Void then(Task<Object> task) {
                    if (task.isFaulted()) {
                        synchronized (errorLock) {
                            causes.add(task.getError());
                        }
                    }
                    if (task.isCancelled()) {
                        isCancelled.set(true);
                    }
                    if (count.decrementAndGet() == 0) {
                        if (causes.size() != 0) {
                            if (causes.size() == 1) {
                                create.setError((Exception) causes.get(0));
                            } else {
                                create.setError(new AggregateException(String.format("There were %d exceptions.", new Object[]{Integer.valueOf(causes.size())}), (List<? extends Throwable>) causes));
                            }
                        } else if (isCancelled.get()) {
                            create.setCancelled();
                        } else {
                            create.setResult(null);
                        }
                    }
                    return null;
                }
            });
        }
        return create.getTask();
    }

    /* JADX WARNING: type inference failed for: r3v0, types: [java.util.concurrent.Callable, java.util.concurrent.Callable<java.lang.Boolean>] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public Task<Void> continueWhile(Callable<Boolean> r3, Continuation<Void, Task<Void>> continuation) {
        return continueWhile(r3, continuation, IMMEDIATE_EXECUTOR, null);
    }

    /* JADX WARNING: type inference failed for: r2v0, types: [java.util.concurrent.Callable, java.util.concurrent.Callable<java.lang.Boolean>] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public Task<Void> continueWhile(Callable<Boolean> r2, Continuation<Void, Task<Void>> continuation, CancellationToken ct) {
        return continueWhile(r2, continuation, IMMEDIATE_EXECUTOR, ct);
    }

    /* JADX WARNING: type inference failed for: r2v0, types: [java.util.concurrent.Callable, java.util.concurrent.Callable<java.lang.Boolean>] */
    /* JADX WARNING: Unknown variable types count: 1 */
    public Task<Void> continueWhile(Callable<Boolean> r2, Continuation<Void, Task<Void>> continuation, Executor executor) {
        return continueWhile(r2, continuation, executor, null);
    }

    public Task<Void> continueWhile(Callable<Boolean> predicate, Continuation<Void, Task<Void>> continuation, Executor executor, CancellationToken ct) {
        final Capture<Continuation<Void, Task<Void>>> predicateContinuation = new Capture<>();
        final CancellationToken cancellationToken = ct;
        final Callable<Boolean> callable = predicate;
        final Continuation<Void, Task<Void>> continuation2 = continuation;
        final Executor executor2 = executor;
        predicateContinuation.set(new Continuation<Void, Task<Void>>() {
            public Task<Void> then(Task<Void> task) throws Exception {
                if (cancellationToken != null && cancellationToken.isCancellationRequested()) {
                    return Task.cancelled();
                }
                if (((Boolean) callable.call()).booleanValue()) {
                    return Task.forResult(null).onSuccessTask(continuation2, executor2).onSuccessTask((Continuation) predicateContinuation.get(), executor2);
                }
                return Task.forResult(null);
            }
        });
        return makeVoid().continueWithTask((Continuation) predicateContinuation.get(), executor);
    }

    public <TContinuationResult> Task<TContinuationResult> continueWith(Continuation<TResult, TContinuationResult> continuation, Executor executor) {
        return continueWith(continuation, executor, null);
    }

    public <TContinuationResult> Task<TContinuationResult> continueWith(Continuation<TResult, TContinuationResult> continuation, Executor executor, CancellationToken ct) {
        boolean completed;
        final TaskCompletionSource create = create();
        synchronized (this.lock) {
            completed = isCompleted();
            if (!completed) {
                final Continuation<TResult, TContinuationResult> continuation2 = continuation;
                final Executor executor2 = executor;
                final CancellationToken cancellationToken = ct;
                this.continuations.add(new Continuation<TResult, Void>() {
                    public Void then(Task<TResult> task) {
                        Task.completeImmediately(create, continuation2, task, executor2, cancellationToken);
                        return null;
                    }
                });
            }
        }
        if (completed) {
            completeImmediately(create, continuation, this, executor, ct);
        }
        return create.getTask();
    }

    public <TContinuationResult> Task<TContinuationResult> continueWith(Continuation<TResult, TContinuationResult> continuation) {
        return continueWith(continuation, IMMEDIATE_EXECUTOR, null);
    }

    public <TContinuationResult> Task<TContinuationResult> continueWith(Continuation<TResult, TContinuationResult> continuation, CancellationToken ct) {
        return continueWith(continuation, IMMEDIATE_EXECUTOR, ct);
    }

    public <TContinuationResult> Task<TContinuationResult> continueWithTask(Continuation<TResult, Task<TContinuationResult>> continuation, Executor executor) {
        return continueWithTask(continuation, executor, null);
    }

    public <TContinuationResult> Task<TContinuationResult> continueWithTask(Continuation<TResult, Task<TContinuationResult>> continuation, Executor executor, CancellationToken ct) {
        boolean completed;
        final TaskCompletionSource create = create();
        synchronized (this.lock) {
            completed = isCompleted();
            if (!completed) {
                final Continuation<TResult, Task<TContinuationResult>> continuation2 = continuation;
                final Executor executor2 = executor;
                final CancellationToken cancellationToken = ct;
                this.continuations.add(new Continuation<TResult, Void>() {
                    public Void then(Task<TResult> task) {
                        Task.completeAfterTask(create, continuation2, task, executor2, cancellationToken);
                        return null;
                    }
                });
            }
        }
        if (completed) {
            completeAfterTask(create, continuation, this, executor, ct);
        }
        return create.getTask();
    }

    public <TContinuationResult> Task<TContinuationResult> continueWithTask(Continuation<TResult, Task<TContinuationResult>> continuation) {
        return continueWithTask(continuation, IMMEDIATE_EXECUTOR, null);
    }

    public <TContinuationResult> Task<TContinuationResult> continueWithTask(Continuation<TResult, Task<TContinuationResult>> continuation, CancellationToken ct) {
        return continueWithTask(continuation, IMMEDIATE_EXECUTOR, ct);
    }

    public <TContinuationResult> Task<TContinuationResult> onSuccess(Continuation<TResult, TContinuationResult> continuation, Executor executor) {
        return onSuccess(continuation, executor, null);
    }

    public <TContinuationResult> Task<TContinuationResult> onSuccess(final Continuation<TResult, TContinuationResult> continuation, Executor executor, final CancellationToken ct) {
        return continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<TResult, Task<TContinuationResult>>() {
            public Task<TContinuationResult> then(Task<TResult> task) {
                if (ct != null && ct.isCancellationRequested()) {
                    return Task.cancelled();
                }
                if (task.isFaulted()) {
                    return Task.forError(task.getError());
                }
                if (task.isCancelled()) {
                    return Task.cancelled();
                }
                return task.continueWith(continuation);
            }
        }, executor);
    }

    public <TContinuationResult> Task<TContinuationResult> onSuccess(Continuation<TResult, TContinuationResult> continuation) {
        return onSuccess(continuation, IMMEDIATE_EXECUTOR, null);
    }

    public <TContinuationResult> Task<TContinuationResult> onSuccess(Continuation<TResult, TContinuationResult> continuation, CancellationToken ct) {
        return onSuccess(continuation, IMMEDIATE_EXECUTOR, ct);
    }

    public <TContinuationResult> Task<TContinuationResult> onSuccessTask(Continuation<TResult, Task<TContinuationResult>> continuation, Executor executor) {
        return onSuccessTask(continuation, executor, null);
    }

    public <TContinuationResult> Task<TContinuationResult> onSuccessTask(final Continuation<TResult, Task<TContinuationResult>> continuation, Executor executor, final CancellationToken ct) {
        return continueWithTask((Continuation<TResult, Task<TContinuationResult>>) new Continuation<TResult, Task<TContinuationResult>>() {
            public Task<TContinuationResult> then(Task<TResult> task) {
                if (ct != null && ct.isCancellationRequested()) {
                    return Task.cancelled();
                }
                if (task.isFaulted()) {
                    return Task.forError(task.getError());
                }
                if (task.isCancelled()) {
                    return Task.cancelled();
                }
                return task.continueWithTask(continuation);
            }
        }, executor);
    }

    public <TContinuationResult> Task<TContinuationResult> onSuccessTask(Continuation<TResult, Task<TContinuationResult>> continuation) {
        return onSuccessTask(continuation, IMMEDIATE_EXECUTOR);
    }

    public <TContinuationResult> Task<TContinuationResult> onSuccessTask(Continuation<TResult, Task<TContinuationResult>> continuation, CancellationToken ct) {
        return onSuccessTask(continuation, IMMEDIATE_EXECUTOR, ct);
    }

    /* access modifiers changed from: private */
    public static <TContinuationResult, TResult> void completeImmediately(final TaskCompletionSource tcs, final Continuation<TResult, TContinuationResult> continuation, final Task<TResult> task, Executor executor, final CancellationToken ct) {
        executor.execute(new Runnable() {
            public void run() {
                if (ct == null || !ct.isCancellationRequested()) {
                    try {
                        tcs.setResult(continuation.then(task));
                    } catch (CancellationException e) {
                        tcs.setCancelled();
                    } catch (Exception e2) {
                        tcs.setError(e2);
                    }
                } else {
                    tcs.setCancelled();
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public static <TContinuationResult, TResult> void completeAfterTask(final TaskCompletionSource tcs, final Continuation<TResult, Task<TContinuationResult>> continuation, final Task<TResult> task, Executor executor, final CancellationToken ct) {
        executor.execute(new Runnable() {
            public void run() {
                if (ct == null || !ct.isCancellationRequested()) {
                    try {
                        Task<TContinuationResult> result = (Task) continuation.then(task);
                        if (result == null) {
                            tcs.setResult(null);
                        } else {
                            result.continueWith(new Continuation<TContinuationResult, Void>() {
                                public Void then(Task<TContinuationResult> task) {
                                    if (ct != null && ct.isCancellationRequested()) {
                                        tcs.setCancelled();
                                    } else if (task.isCancelled()) {
                                        tcs.setCancelled();
                                    } else if (task.isFaulted()) {
                                        tcs.setError(task.getError());
                                    } else {
                                        tcs.setResult(task.getResult());
                                    }
                                    return null;
                                }
                            });
                        }
                    } catch (CancellationException e) {
                        tcs.setCancelled();
                    } catch (Exception e2) {
                        tcs.setError(e2);
                    }
                } else {
                    tcs.setCancelled();
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void runContinuations() {
        synchronized (this.lock) {
            for (Continuation<TResult, ?> continuation : this.continuations) {
                try {
                    continuation.then(this);
                } catch (RuntimeException e) {
                    throw e;
                } catch (Exception e2) {
                    throw new RuntimeException(e2);
                }
            }
            this.continuations = null;
        }
    }
}