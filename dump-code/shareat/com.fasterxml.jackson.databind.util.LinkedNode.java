package com.fasterxml.jackson.databind.util;

public final class LinkedNode<T> {
    final LinkedNode<T> _next;
    final T _value;

    public LinkedNode(T t, LinkedNode<T> linkedNode) {
        this._value = t;
        this._next = linkedNode;
    }

    public LinkedNode<T> next() {
        return this._next;
    }

    public T value() {
        return this._value;
    }

    public static <ST> boolean contains(LinkedNode<ST> linkedNode, ST st) {
        while (linkedNode != null) {
            if (linkedNode.value() == st) {
                return true;
            }
            linkedNode = linkedNode.next();
        }
        return false;
    }
}