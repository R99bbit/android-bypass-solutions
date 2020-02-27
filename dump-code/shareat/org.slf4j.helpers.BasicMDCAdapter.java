package org.slf4j.helpers;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import org.slf4j.spi.MDCAdapter;

public class BasicMDCAdapter implements MDCAdapter {
    static boolean IS_JDK14 = isJDK14();
    private InheritableThreadLocal inheritableThreadLocal = new InheritableThreadLocal();

    static boolean isJDK14() {
        try {
            return System.getProperty("java.version").startsWith("1.4");
        } catch (SecurityException e) {
            return false;
        }
    }

    public void put(String key, String val) {
        if (key == null) {
            throw new IllegalArgumentException("key cannot be null");
        }
        Map map = (Map) this.inheritableThreadLocal.get();
        if (map == null) {
            map = Collections.synchronizedMap(new HashMap());
            this.inheritableThreadLocal.set(map);
        }
        map.put(key, val);
    }

    public String get(String key) {
        Map Map = (Map) this.inheritableThreadLocal.get();
        if (Map == null || key == null) {
            return null;
        }
        return (String) Map.get(key);
    }

    public void remove(String key) {
        Map map = (Map) this.inheritableThreadLocal.get();
        if (map != null) {
            map.remove(key);
        }
    }

    public void clear() {
        Map map = (Map) this.inheritableThreadLocal.get();
        if (map != null) {
            map.clear();
            if (isJDK14()) {
                this.inheritableThreadLocal.set(null);
            } else {
                this.inheritableThreadLocal.remove();
            }
        }
    }

    public Set getKeys() {
        Map map = (Map) this.inheritableThreadLocal.get();
        if (map != null) {
            return map.keySet();
        }
        return null;
    }

    public Map getCopyOfContextMap() {
        Map oldMap = (Map) this.inheritableThreadLocal.get();
        if (oldMap == null) {
            return null;
        }
        Map newMap = Collections.synchronizedMap(new HashMap());
        synchronized (oldMap) {
            newMap.putAll(oldMap);
        }
        return newMap;
    }

    public void setContextMap(Map contextMap) {
        this.inheritableThreadLocal.set(Collections.synchronizedMap(new HashMap(contextMap)));
    }
}