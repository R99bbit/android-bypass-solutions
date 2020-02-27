package com.fasterxml.jackson.databind.util;

import java.util.Collection;

@Deprecated
public interface Provider<T> {
    Collection<T> provide();
}