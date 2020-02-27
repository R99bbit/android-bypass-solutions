package com.igaworks.util.image;

import android.os.Environment;
import io.fabric.sdk.android.services.common.CommonUtils;
import io.fabric.sdk.android.services.events.EventsFilesManager;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class FileCacheImpl implements FileCache {
    public static final String IGAW_CACHE_PATH = "/igaw/";
    private CacheStorage cacheStorage;

    public FileCacheImpl(File cacheDir, int maxKBSizes) {
        this.cacheStorage = new CacheStorage(cacheDir, (long) (maxKBSizes <= 0 ? 0 : maxKBSizes * 1024));
    }

    public FileEntry get(String key) {
        try {
            File mFile1 = new File(new StringBuilder(String.valueOf(Environment.getExternalStorageDirectory().getAbsolutePath())).append(IGAW_CACHE_PATH).toString());
            if (!mFile1.exists()) {
                mFile1.mkdirs();
            }
            File mFile2 = new File(mFile1, computeHashedName(key));
            if (mFile2.exists()) {
                return new FileEntry(key, mFile2);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public void put(String key, ByteProvider provider) throws IOException {
        this.cacheStorage.write(keyToFilename(key), provider);
    }

    public void put(String key, InputStream is) throws IOException {
        put(key, ByteProviderUtil.create(is));
    }

    public void put(String key, File sourceFile, boolean move) throws IOException {
        if (move) {
            this.cacheStorage.move(keyToFilename(key), sourceFile);
        } else {
            put(key, ByteProviderUtil.create(sourceFile));
        }
    }

    public void remove(String key) {
        this.cacheStorage.delete(keyToFilename(key));
    }

    private String keyToFilename(String key) {
        return key.replace(":", EventsFilesManager.ROLL_OVER_FILE_NAME_SEPARATOR).replace("/", "_s_").replace("\\", "_bs_").replace("&", "_bs_").replace("*", "_start_").replace("?", "_q_").replace("|", "_or_").replace(">", "_gt_").replace("<", "_lt_");
    }

    public void clear() {
        this.cacheStorage.deleteAll();
    }

    public static String computeHashedName(String name) {
        try {
            MessageDigest digest = MessageDigest.getInstance(CommonUtils.MD5_INSTANCE);
            digest.update(name.getBytes());
            byte[] result = digest.digest();
            return String.format("%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", new Object[]{Byte.valueOf(result[0]), Byte.valueOf(result[1]), Byte.valueOf(result[2]), Byte.valueOf(result[3]), Byte.valueOf(result[4]), Byte.valueOf(result[5]), Byte.valueOf(result[6]), Byte.valueOf(result[7]), Byte.valueOf(result[8]), Byte.valueOf(result[9]), Byte.valueOf(result[10]), Byte.valueOf(result[11]), Byte.valueOf(result[12]), Byte.valueOf(result[13]), Byte.valueOf(result[14]), Byte.valueOf(result[15])});
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}