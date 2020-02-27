package org.jboss.netty.handler.codec.serialization;

class ClassLoaderClassResolver implements ClassResolver {
    private final ClassLoader classLoader;

    ClassLoaderClassResolver(ClassLoader classLoader2) {
        this.classLoader = classLoader2;
    }

    public Class<?> resolve(String className) throws ClassNotFoundException {
        try {
            return this.classLoader.loadClass(className);
        } catch (ClassNotFoundException e) {
            return Class.forName(className, false, this.classLoader);
        }
    }
}