package org.slf4j.spi;

import java.util.Map;

public interface MDCAdapter {
    void clear();

    String get(String str);

    Map getCopyOfContextMap();

    void put(String str, String str2);

    void remove(String str);

    void setContextMap(Map map);
}