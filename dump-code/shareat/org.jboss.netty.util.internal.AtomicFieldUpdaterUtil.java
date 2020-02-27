package org.jboss.netty.util.internal;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;

final class AtomicFieldUpdaterUtil {
    private static final boolean AVAILABLE;

    static final class Node {
        volatile Node next;

        Node() {
        }
    }

    static {
        boolean available = false;
        try {
            AtomicReferenceFieldUpdater<Node, Node> tmp = AtomicReferenceFieldUpdater.newUpdater(Node.class, Node.class, "next");
            Node testNode = new Node();
            tmp.set(testNode, testNode);
            if (testNode.next != testNode) {
                throw new Exception();
            }
            available = true;
            AVAILABLE = available;
        } catch (Throwable th) {
        }
    }

    static <T, V> AtomicReferenceFieldUpdater<T, V> newRefUpdater(Class<T> tclass, Class<V> vclass, String fieldName) {
        if (AVAILABLE) {
            return AtomicReferenceFieldUpdater.newUpdater(tclass, vclass, fieldName);
        }
        return null;
    }

    static <T> AtomicIntegerFieldUpdater<T> newIntUpdater(Class<T> tclass, String fieldName) {
        if (AVAILABLE) {
            return AtomicIntegerFieldUpdater.newUpdater(tclass, fieldName);
        }
        return null;
    }

    static boolean isAvailable() {
        return AVAILABLE;
    }

    private AtomicFieldUpdaterUtil() {
    }
}