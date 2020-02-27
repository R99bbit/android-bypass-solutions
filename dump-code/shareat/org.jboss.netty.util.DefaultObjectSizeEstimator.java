package org.jboss.netty.util;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentMap;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.util.internal.ConcurrentIdentityWeakKeyHashMap;

public class DefaultObjectSizeEstimator implements ObjectSizeEstimator {
    private final ConcurrentMap<Class<?>, Integer> class2size = new ConcurrentIdentityWeakKeyHashMap();

    public DefaultObjectSizeEstimator() {
        this.class2size.put(Boolean.TYPE, Integer.valueOf(4));
        this.class2size.put(Byte.TYPE, Integer.valueOf(1));
        this.class2size.put(Character.TYPE, Integer.valueOf(2));
        this.class2size.put(Integer.TYPE, Integer.valueOf(4));
        this.class2size.put(Short.TYPE, Integer.valueOf(2));
        this.class2size.put(Long.TYPE, Integer.valueOf(8));
        this.class2size.put(Float.TYPE, Integer.valueOf(4));
        this.class2size.put(Double.TYPE, Integer.valueOf(8));
        this.class2size.put(Void.TYPE, Integer.valueOf(0));
    }

    public int estimateSize(Object o) {
        if (o == null) {
            return 8;
        }
        int answer = estimateSize(o.getClass(), null) + 8;
        if (o instanceof EstimatableObjectWrapper) {
            answer += estimateSize(((EstimatableObjectWrapper) o).unwrap());
        } else if (o instanceof MessageEvent) {
            answer += estimateSize(((MessageEvent) o).getMessage());
        } else if (o instanceof ChannelBuffer) {
            answer += ((ChannelBuffer) o).capacity();
        } else if (o instanceof byte[]) {
            answer += ((byte[]) o).length;
        } else if (o instanceof ByteBuffer) {
            answer += ((ByteBuffer) o).remaining();
        } else if (o instanceof CharSequence) {
            answer += ((CharSequence) o).length() << 1;
        } else if (o instanceof Iterable) {
            for (Object m : (Iterable) o) {
                answer += estimateSize(m);
            }
        }
        return align(answer);
    }

    /* JADX WARNING: Incorrect type for immutable var: ssa=java.lang.Class<?>, code=java.lang.Class, for r11v0, types: [java.lang.Class<?>, java.lang.Class, java.lang.Object] */
    private int estimateSize(Class clazz, Set<Class<?>> visitedClasses) {
        Field[] arr$;
        Integer objectSize = (Integer) this.class2size.get(clazz);
        if (objectSize != null) {
            return objectSize.intValue();
        }
        if (visitedClasses == null) {
            visitedClasses = new HashSet<>();
        } else if (visitedClasses.contains(clazz)) {
            return 0;
        }
        visitedClasses.add(clazz);
        int answer = 8;
        for (Class cls = clazz; cls != null; cls = cls.getSuperclass()) {
            for (Field f : cls.getDeclaredFields()) {
                if ((f.getModifiers() & 8) == 0) {
                    answer += estimateSize(f.getType(), visitedClasses);
                }
            }
        }
        visitedClasses.remove(clazz);
        int answer2 = align(answer);
        this.class2size.putIfAbsent(clazz, Integer.valueOf(answer2));
        return answer2;
    }

    private static int align(int size) {
        int r = size % 8;
        if (r != 0) {
            return size + (8 - r);
        }
        return size;
    }
}