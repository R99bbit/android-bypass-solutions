package de.greenrobot.event;

import android.util.Log;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

class SubscriberMethodFinder {
    private static final int MODIFIERS_IGNORE = 1032;
    private static final Map<String, List<SubscriberMethod>> methodCache = new HashMap();
    private static final Map<Class<?>, Class<?>> skipMethodVerificationForClasses = new ConcurrentHashMap();

    SubscriberMethodFinder() {
    }

    /* access modifiers changed from: 0000 */
    /* JADX WARNING: Incorrect type for immutable var: ssa=java.lang.Class<?>, code=java.lang.Class, for r25v0, types: [java.lang.Class<?>, java.lang.Class] */
    public List<SubscriberMethod> findSubscriberMethods(Class subscriberClass, String eventMethodName) {
        List<SubscriberMethod> subscriberMethods;
        Method[] arr$;
        ThreadMode threadMode;
        String key = subscriberClass.getName() + '.' + eventMethodName;
        synchronized (methodCache) {
            try {
                subscriberMethods = methodCache.get(key);
            }
        }
        if (subscriberMethods != null) {
            return subscriberMethods;
        }
        List<SubscriberMethod> subscriberMethods2 = new ArrayList<>();
        HashSet<String> eventTypesFound = new HashSet<>();
        StringBuilder methodKeyBuilder = new StringBuilder();
        for (Class cls = subscriberClass; cls != null; cls = cls.getSuperclass()) {
            String name = cls.getName();
            if (name.startsWith("java.") || name.startsWith("javax.") || name.startsWith("android.")) {
                break;
            }
            for (Method method : cls.getMethods()) {
                String methodName = method.getName();
                if (methodName.startsWith(eventMethodName)) {
                    int modifiers = method.getModifiers();
                    if ((modifiers & 1) != 0 && (modifiers & MODIFIERS_IGNORE) == 0) {
                        Class<?>[] parameterTypes = method.getParameterTypes();
                        if (parameterTypes.length == 1) {
                            String modifierString = methodName.substring(eventMethodName.length());
                            if (modifierString.length() == 0) {
                                threadMode = ThreadMode.PostThread;
                            } else if (modifierString.equals("MainThread")) {
                                threadMode = ThreadMode.MainThread;
                            } else if (modifierString.equals("BackgroundThread")) {
                                threadMode = ThreadMode.BackgroundThread;
                            } else if (modifierString.equals("Async")) {
                                threadMode = ThreadMode.Async;
                            } else if (!skipMethodVerificationForClasses.containsKey(cls)) {
                                throw new EventBusException("Illegal onEvent method, check for typos: " + method);
                            }
                            Class<?> eventType = parameterTypes[0];
                            methodKeyBuilder.setLength(0);
                            methodKeyBuilder.append(methodName);
                            methodKeyBuilder.append('>').append(eventType.getName());
                            if (eventTypesFound.add(methodKeyBuilder.toString())) {
                                SubscriberMethod subscriberMethod = new SubscriberMethod(method, threadMode, eventType);
                                subscriberMethods2.add(subscriberMethod);
                            }
                        } else {
                            continue;
                        }
                    } else if (!skipMethodVerificationForClasses.containsKey(cls)) {
                        Log.d(EventBus.TAG, "Skipping method (not public, static or abstract): " + cls + "." + methodName);
                    }
                }
            }
        }
        if (subscriberMethods2.isEmpty()) {
            throw new EventBusException("Subscriber " + subscriberClass + " has no public methods called " + eventMethodName);
        }
        synchronized (methodCache) {
            try {
                methodCache.put(key, subscriberMethods2);
            }
        }
        return subscriberMethods2;
    }

    static void clearCaches() {
        synchronized (methodCache) {
            methodCache.clear();
        }
    }

    static void skipMethodVerificationFor(Class<?> clazz) {
        if (!methodCache.isEmpty()) {
            throw new IllegalStateException("This method must be called before registering anything");
        }
        skipMethodVerificationForClasses.put(clazz, clazz);
    }

    public static void clearSkipMethodVerifications() {
        skipMethodVerificationForClasses.clear();
    }
}