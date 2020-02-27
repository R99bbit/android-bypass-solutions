package org.jboss.netty.handler.codec.serialization;

import java.util.Map;

class CachingClassResolver implements ClassResolver {
    private final Map<String, Class<?>> classCache;
    private final ClassResolver delegate;

    CachingClassResolver(ClassResolver delegate2, Map<String, Class<?>> classCache2) {
        this.delegate = delegate2;
        this.classCache = classCache2;
    }

    public Class<?> resolve(String className) throws ClassNotFoundException {
        Class<?> clazz = this.classCache.get(className);
        if (clazz != null) {
            return clazz;
        }
        Class<?> clazz2 = this.delegate.resolve(className);
        this.classCache.put(className, clazz2);
        return clazz2;
    }
}