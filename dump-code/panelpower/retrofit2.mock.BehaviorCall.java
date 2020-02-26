package retrofit2.mock;

import java.io.IOException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import okhttp3.Request;
import retrofit2.Call;
import retrofit2.Callback;
import retrofit2.Response;

final class BehaviorCall<T> implements Call<T> {
    final ExecutorService backgroundExecutor;
    final NetworkBehavior behavior;
    volatile boolean canceled;
    final Call<T> delegate;
    private volatile boolean executed;
    private volatile Future<?> task;

    BehaviorCall(NetworkBehavior networkBehavior, ExecutorService executorService, Call<T> call) {
        this.behavior = networkBehavior;
        this.backgroundExecutor = executorService;
        this.delegate = call;
    }

    public Call<T> clone() {
        return new BehaviorCall(this.behavior, this.backgroundExecutor, this.delegate.clone());
    }

    public Request request() {
        return this.delegate.request();
    }

    public void enqueue(final Callback<T> callback) {
        if (callback != null) {
            synchronized (this) {
                if (!this.executed) {
                    this.executed = true;
                } else {
                    throw new IllegalStateException("Already executed");
                }
            }
            this.task = this.backgroundExecutor.submit(new Runnable() {
                /* access modifiers changed from: 0000 */
                public boolean delaySleep() {
                    long calculateDelay = BehaviorCall.this.behavior.calculateDelay(TimeUnit.MILLISECONDS);
                    if (calculateDelay > 0) {
                        try {
                            Thread.sleep(calculateDelay);
                        } catch (InterruptedException unused) {
                            callback.onFailure(BehaviorCall.this, new IOException("canceled"));
                            return false;
                        }
                    }
                    return true;
                }

                public void run() {
                    if (BehaviorCall.this.canceled) {
                        callback.onFailure(BehaviorCall.this, new IOException("canceled"));
                    } else if (!BehaviorCall.this.behavior.calculateIsFailure()) {
                        BehaviorCall.this.delegate.enqueue(new Callback<T>() {
                            public void onResponse(Call<T> call, Response<T> response) {
                                if (AnonymousClass1.this.delaySleep()) {
                                    callback.onResponse(call, response);
                                }
                            }

                            public void onFailure(Call<T> call, Throwable th) {
                                if (AnonymousClass1.this.delaySleep()) {
                                    callback.onFailure(call, th);
                                }
                            }
                        });
                    } else if (delaySleep()) {
                        Callback callback = callback;
                        BehaviorCall behaviorCall = BehaviorCall.this;
                        callback.onFailure(behaviorCall, behaviorCall.behavior.failureException());
                    }
                }
            });
            return;
        }
        throw new NullPointerException("callback == null");
    }

    public synchronized boolean isExecuted() {
        return this.executed;
    }

    public Response<T> execute() throws IOException {
        final AtomicReference atomicReference = new AtomicReference();
        final AtomicReference atomicReference2 = new AtomicReference();
        final CountDownLatch countDownLatch = new CountDownLatch(1);
        enqueue(new Callback<T>() {
            public void onResponse(Call<T> call, Response<T> response) {
                atomicReference.set(response);
                countDownLatch.countDown();
            }

            public void onFailure(Call<T> call, Throwable th) {
                atomicReference2.set(th);
                countDownLatch.countDown();
            }
        });
        try {
            countDownLatch.await();
            Response<T> response = (Response) atomicReference.get();
            if (response != null) {
                return response;
            }
            Throwable th = (Throwable) atomicReference2.get();
            if (th instanceof RuntimeException) {
                throw ((RuntimeException) th);
            } else if (th instanceof IOException) {
                throw ((IOException) th);
            } else {
                throw new RuntimeException(th);
            }
        } catch (InterruptedException unused) {
            throw new IOException("canceled");
        }
    }

    public void cancel() {
        this.canceled = true;
        Future<?> future = this.task;
        if (future != null) {
            future.cancel(true);
        }
    }

    public boolean isCanceled() {
        return this.canceled;
    }
}