package retrofit2.mock;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.concurrent.ExecutorService;
import retrofit2.Call;
import retrofit2.Retrofit;

public final class BehaviorDelegate<T> {
    private final NetworkBehavior behavior;
    private final ExecutorService executor;
    final Retrofit retrofit;
    private final Class<T> service;

    BehaviorDelegate(Retrofit retrofit3, NetworkBehavior networkBehavior, ExecutorService executorService, Class<T> cls) {
        this.retrofit = retrofit3;
        this.behavior = networkBehavior;
        this.executor = executorService;
        this.service = cls;
    }

    public T returningResponse(Object obj) {
        return returning(Calls.response(obj));
    }

    public T returning(Call<?> call) {
        final BehaviorCall behaviorCall = new BehaviorCall(this.behavior, this.executor, call);
        return Proxy.newProxyInstance(this.service.getClassLoader(), new Class[]{this.service}, new InvocationHandler() {
            public Object invoke(Object obj, Method method, Object[] objArr) throws Throwable {
                return BehaviorDelegate.this.retrofit.callAdapter(method.getGenericReturnType(), method.getAnnotations()).adapt(behaviorCall);
            }
        });
    }
}