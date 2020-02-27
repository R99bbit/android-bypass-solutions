package com.nuvent.shareat.util.crop.camera;

import android.content.ContentResolver;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.BitmapFactory.Options;
import android.provider.MediaStore.Images.Thumbnails;
import android.provider.MediaStore.Video;
import android.util.Log;
import java.io.FileDescriptor;
import java.util.WeakHashMap;

public class BitmapManager {
    private static final String TAG = "BitmapManager";
    private static BitmapManager sManager = null;
    private final WeakHashMap<Thread, ThreadStatus> mThreadStatus = new WeakHashMap<>();

    private enum State {
        CANCEL,
        ALLOW
    }

    private static class ThreadStatus {
        public Options mOptions;
        public State mState;
        public boolean mThumbRequesting;

        private ThreadStatus() {
            this.mState = State.ALLOW;
        }

        public String toString() {
            String s;
            if (this.mState == State.CANCEL) {
                s = "Cancel";
            } else if (this.mState == State.ALLOW) {
                s = "Allow";
            } else {
                s = "?";
            }
            return "thread state = " + s + ", options = " + this.mOptions;
        }
    }

    private BitmapManager() {
    }

    private synchronized ThreadStatus getOrCreateThreadStatus(Thread t) {
        ThreadStatus status;
        status = this.mThreadStatus.get(t);
        if (status == null) {
            status = new ThreadStatus();
            this.mThreadStatus.put(t, status);
        }
        return status;
    }

    private synchronized void setDecodingOptions(Thread t, Options options) {
        getOrCreateThreadStatus(t).mOptions = options;
    }

    /* access modifiers changed from: 0000 */
    public synchronized void removeDecodingOptions(Thread t) {
        this.mThreadStatus.get(t).mOptions = null;
    }

    public synchronized boolean canThreadDecoding(Thread t) {
        boolean result = true;
        synchronized (this) {
            ThreadStatus status = this.mThreadStatus.get(t);
            if (status != null) {
                if (status.mState == State.CANCEL) {
                    result = false;
                }
            }
        }
        return result;
    }

    public synchronized void allowThreadDecoding(Thread t) {
        getOrCreateThreadStatus(t).mState = State.ALLOW;
    }

    public synchronized void cancelThreadDecoding(Thread t, ContentResolver cr) {
        ThreadStatus status = getOrCreateThreadStatus(t);
        status.mState = State.CANCEL;
        if (status.mOptions != null) {
            status.mOptions.requestCancelDecode();
        }
        notifyAll();
        try {
            synchronized (status) {
                while (status.mThumbRequesting) {
                    Thumbnails.cancelThumbnailRequest(cr, -1, t.getId());
                    Video.Thumbnails.cancelThumbnailRequest(cr, -1, t.getId());
                    status.wait(200);
                }
            }
        } catch (InterruptedException e) {
        }
    }

    public Bitmap getThumbnail(ContentResolver cr, long origId, int kind, Options options, boolean isVideo) {
        Bitmap bitmap = null;
        Thread t = Thread.currentThread();
        ThreadStatus status = getOrCreateThreadStatus(t);
        if (!canThreadDecoding(t)) {
            Log.d(TAG, "Thread " + t + " is not allowed to decode.");
        } else {
            try {
                synchronized (status) {
                    status.mThumbRequesting = true;
                }
                if (isVideo) {
                    bitmap = Video.Thumbnails.getThumbnail(cr, origId, t.getId(), kind, null);
                    synchronized (status) {
                        try {
                            status.mThumbRequesting = false;
                            status.notifyAll();
                        }
                    }
                } else {
                    bitmap = Thumbnails.getThumbnail(cr, origId, t.getId(), kind, null);
                    synchronized (status) {
                        try {
                            status.mThumbRequesting = false;
                            status.notifyAll();
                        }
                    }
                }
            } finally {
                synchronized (status) {
                    status.mThumbRequesting = false;
                    status.notifyAll();
                }
            }
        }
        return bitmap;
    }

    public static synchronized BitmapManager instance() {
        BitmapManager bitmapManager;
        synchronized (BitmapManager.class) {
            try {
                if (sManager == null) {
                    sManager = new BitmapManager();
                }
                bitmapManager = sManager;
            }
        }
        return bitmapManager;
    }

    public Bitmap decodeFileDescriptor(FileDescriptor fd, Options options) {
        if (options.mCancel) {
            return null;
        }
        Thread thread = Thread.currentThread();
        if (!canThreadDecoding(thread)) {
            Log.d(TAG, "Thread " + thread + " is not allowed to decode.");
            return null;
        }
        setDecodingOptions(thread, options);
        Bitmap decodeFileDescriptor = BitmapFactory.decodeFileDescriptor(fd, null, options);
        removeDecodingOptions(thread);
        return decodeFileDescriptor;
    }
}