package com.igaworks.util.image;

import android.content.Context;
import java.io.File;
import java.util.HashMap;

public class FileCacheFactory {
    private static boolean initialized = false;
    private static FileCacheFactory instance = new FileCacheFactory();
    private File cacheBaseDir;
    private HashMap<String, FileCache> cacheMap = new HashMap<>();

    public static void initialize(Context context) {
        if (!initialized) {
            synchronized (instance) {
                if (!initialized) {
                    instance.init(context);
                    initialized = true;
                }
            }
        }
    }

    public static FileCacheFactory getInstance() {
        if (initialized) {
            return instance;
        }
        throw new IllegalStateException("Not initialized. You must call FileCacheFactory.initialize() before getInstance()");
    }

    private FileCacheFactory() {
    }

    private void init(Context context) {
        this.cacheBaseDir = context.getCacheDir();
    }

    public FileCache create(String cacheName, int maxKbSizes) {
        FileCache cache;
        synchronized (this.cacheMap) {
            if (this.cacheMap.get(cacheName) != null) {
                try {
                    throw new FileCacheAleadyExistException(String.format("FileCache[%s] Aleady exists", new Object[]{cacheName}));
                } catch (FileCacheAleadyExistException e) {
                }
            }
            cache = new FileCacheImpl(new File(this.cacheBaseDir, cacheName), maxKbSizes);
            this.cacheMap.put(cacheName, cache);
        }
        return cache;
    }

    public FileCache get(String cacheName) {
        FileCache cache;
        synchronized (this.cacheMap) {
            cache = this.cacheMap.get(cacheName);
            if (cache == null) {
                try {
                    throw new FileCacheNotFoundException(String.format("FileCache[%s] not founds.", new Object[]{cacheName}));
                } catch (FileCacheNotFoundException e) {
                }
            }
        }
        return cache;
    }

    public boolean has(String cacheName) {
        return this.cacheMap.containsKey(cacheName);
    }
}