package org.acra.util;

import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;

public class BoundedLinkedList<E> extends LinkedList<E> {
    private final int maxSize;

    public BoundedLinkedList(int i) {
        this.maxSize = i;
    }

    public boolean add(E e) {
        if (size() == this.maxSize) {
            removeFirst();
        }
        return super.add(e);
    }

    public void add(int i, E e) {
        if (size() == this.maxSize) {
            removeFirst();
        }
        super.add(i, e);
    }

    public boolean addAll(Collection<? extends E> collection) {
        int size = (size() + collection.size()) - this.maxSize;
        if (size > 0) {
            removeRange(0, size);
        }
        return super.addAll(collection);
    }

    public boolean addAll(int i, Collection<? extends E> collection) {
        throw new UnsupportedOperationException();
    }

    public void addFirst(E e) {
        throw new UnsupportedOperationException();
    }

    public void addLast(E e) {
        add(e);
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();
        Iterator it = iterator();
        while (it.hasNext()) {
            sb.append(it.next().toString());
        }
        return sb.toString();
    }
}