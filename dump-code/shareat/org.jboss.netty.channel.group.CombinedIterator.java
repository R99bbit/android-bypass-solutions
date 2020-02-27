package org.jboss.netty.channel.group;

import java.util.Iterator;
import java.util.NoSuchElementException;

final class CombinedIterator<E> implements Iterator<E> {
    private Iterator<E> currentIterator;
    private final Iterator<E> i1;
    private final Iterator<E> i2;

    CombinedIterator(Iterator<E> i12, Iterator<E> i22) {
        if (i12 == null) {
            throw new NullPointerException("i1");
        } else if (i22 == null) {
            throw new NullPointerException("i2");
        } else {
            this.i1 = i12;
            this.i2 = i22;
            this.currentIterator = i12;
        }
    }

    public boolean hasNext() {
        while (!this.currentIterator.hasNext()) {
            if (this.currentIterator != this.i1) {
                return false;
            }
            this.currentIterator = this.i2;
        }
        return true;
    }

    public E next() {
        while (true) {
            try {
                return this.currentIterator.next();
            } catch (NoSuchElementException e) {
                if (this.currentIterator == this.i1) {
                    this.currentIterator = this.i2;
                } else {
                    throw e;
                }
            }
        }
    }

    public void remove() {
        this.currentIterator.remove();
    }
}