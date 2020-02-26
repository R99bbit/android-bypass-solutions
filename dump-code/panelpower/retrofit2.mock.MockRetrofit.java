package retrofit2.mock;

import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import retrofit2.Retrofit;

public final class MockRetrofit {
    private final NetworkBehavior behavior;
    private final ExecutorService executor;
    private final Retrofit retrofit;

    public static final class Builder {
        private NetworkBehavior behavior;
        private ExecutorService executor;
        private final Retrofit retrofit;

        public Builder(Retrofit retrofit3) {
            if (retrofit3 != null) {
                this.retrofit = retrofit3;
                return;
            }
            throw new NullPointerException("retrofit == null");
        }

        public Builder networkBehavior(NetworkBehavior networkBehavior) {
            if (networkBehavior != null) {
                this.behavior = networkBehavior;
                return this;
            }
            throw new NullPointerException("behavior == null");
        }

        public Builder backgroundExecutor(ExecutorService executorService) {
            if (executorService != null) {
                this.executor = executorService;
                return this;
            }
            throw new NullPointerException("executor == null");
        }

        public MockRetrofit build() {
            if (this.behavior == null) {
                this.behavior = NetworkBehavior.create();
            }
            if (this.executor == null) {
                this.executor = Executors.newCachedThreadPool();
            }
            return new MockRetrofit(this.retrofit, this.behavior, this.executor);
        }
    }

    MockRetrofit(Retrofit retrofit3, NetworkBehavior networkBehavior, ExecutorService executorService) {
        this.retrofit = retrofit3;
        this.behavior = networkBehavior;
        this.executor = executorService;
    }

    public Retrofit retrofit() {
        return this.retrofit;
    }

    public NetworkBehavior networkBehavior() {
        return this.behavior;
    }

    public Executor backgroundExecutor() {
        return this.executor;
    }

    public <T> BehaviorDelegate<T> create(Class<T> cls) {
        return new BehaviorDelegate<>(this.retrofit, this.behavior, this.executor, cls);
    }
}