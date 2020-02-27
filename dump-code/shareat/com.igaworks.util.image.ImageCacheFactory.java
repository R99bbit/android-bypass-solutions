package com.igaworks.util.image;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

public class ImageCacheFactory {
    private static ImageCacheFactory instance = new ImageCacheFactory();
    private HashMap<String, ImageCache> cacheMap = new HashMap<>();

    public static ImageCacheFactory getInstance() {
        return instance;
    }

    private ImageCacheFactory() {
    }

    public ImageCache createMemoryCache(String cacheName, int imageMaxCounts) {
        ImageCache cache;
        synchronized (this.cacheMap) {
            checkAleadyExists(cacheName);
            cache = new MemoryImageCache(imageMaxCounts);
            this.cacheMap.put(cacheName, cache);
        }
        return cache;
    }

    private void checkAleadyExists(String cacheName) {
        if (this.cacheMap.get(cacheName) != null) {
            try {
                throw new ImageCacheAleadyExistException(String.format("ImageCache[%s] aleady exists", new Object[]{cacheName}));
            } catch (ImageCacheAleadyExistException e) {
            }
        }
    }

    public ImageCache createTwoLevelCache(String cacheName, int imageMaxCounts) {
        ChainedImageCache cache;
        synchronized (this.cacheMap) {
            checkAleadyExists(cacheName);
            List<ImageCache> chain = new ArrayList<>();
            chain.add(new MemoryImageCache(imageMaxCounts));
            chain.add(new FileImageCache(cacheName));
            cache = new ChainedImageCache(chain);
            this.cacheMap.put(cacheName, cache);
        }
        return cache;
    }

    public ImageCache get(String cacheName) {
        ImageCache cache = this.cacheMap.get(cacheName);
        if (cache == null) {
            try {
                throw new ImageCacheNotFoundException(String.format("ImageCache[%s] not founds", new Object[]{cacheName}));
            } catch (ImageCacheNotFoundException e) {
                e.printStackTrace();
            }
        }
        return cache;
    }

    public boolean has(String cacheName) {
        return this.cacheMap.containsKey(cacheName);
    }
}