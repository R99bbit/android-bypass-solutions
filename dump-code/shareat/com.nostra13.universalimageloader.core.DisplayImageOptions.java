package com.nostra13.universalimageloader.core;

import android.content.res.Resources;
import android.graphics.Bitmap.Config;
import android.graphics.BitmapFactory.Options;
import android.graphics.drawable.Drawable;
import android.os.Handler;
import com.nostra13.universalimageloader.core.assist.ImageScaleType;
import com.nostra13.universalimageloader.core.display.BitmapDisplayer;
import com.nostra13.universalimageloader.core.process.BitmapProcessor;

public final class DisplayImageOptions {
    /* access modifiers changed from: private */
    public final boolean cacheInMemory;
    /* access modifiers changed from: private */
    public final boolean cacheOnDisk;
    /* access modifiers changed from: private */
    public final boolean considerExifParams;
    /* access modifiers changed from: private */
    public final Options decodingOptions;
    /* access modifiers changed from: private */
    public final int delayBeforeLoading;
    /* access modifiers changed from: private */
    public final BitmapDisplayer displayer;
    /* access modifiers changed from: private */
    public final Object extraForDownloader;
    /* access modifiers changed from: private */
    public final Handler handler;
    /* access modifiers changed from: private */
    public final Drawable imageForEmptyUri;
    /* access modifiers changed from: private */
    public final Drawable imageOnFail;
    /* access modifiers changed from: private */
    public final Drawable imageOnLoading;
    /* access modifiers changed from: private */
    public final int imageResForEmptyUri;
    /* access modifiers changed from: private */
    public final int imageResOnFail;
    /* access modifiers changed from: private */
    public final int imageResOnLoading;
    /* access modifiers changed from: private */
    public final ImageScaleType imageScaleType;
    /* access modifiers changed from: private */
    public final boolean isSyncLoading;
    /* access modifiers changed from: private */
    public final BitmapProcessor postProcessor;
    /* access modifiers changed from: private */
    public final BitmapProcessor preProcessor;
    /* access modifiers changed from: private */
    public final boolean resetViewBeforeLoading;

    public static class Builder {
        /* access modifiers changed from: private */
        public boolean cacheInMemory;
        /* access modifiers changed from: private */
        public boolean cacheOnDisk;
        /* access modifiers changed from: private */
        public boolean considerExifParams;
        /* access modifiers changed from: private */
        public Options decodingOptions;
        /* access modifiers changed from: private */
        public int delayBeforeLoading;
        /* access modifiers changed from: private */
        public BitmapDisplayer displayer;
        /* access modifiers changed from: private */
        public Object extraForDownloader;
        /* access modifiers changed from: private */
        public Handler handler;
        /* access modifiers changed from: private */
        public Drawable imageForEmptyUri;
        /* access modifiers changed from: private */
        public Drawable imageOnFail;
        /* access modifiers changed from: private */
        public Drawable imageOnLoading;
        /* access modifiers changed from: private */
        public int imageResForEmptyUri;
        /* access modifiers changed from: private */
        public int imageResOnFail;
        /* access modifiers changed from: private */
        public int imageResOnLoading;
        /* access modifiers changed from: private */
        public ImageScaleType imageScaleType;
        /* access modifiers changed from: private */
        public boolean isSyncLoading;
        /* access modifiers changed from: private */
        public BitmapProcessor postProcessor;
        /* access modifiers changed from: private */
        public BitmapProcessor preProcessor;
        /* access modifiers changed from: private */
        public boolean resetViewBeforeLoading;

        public Builder() {
            this.imageResOnLoading = 0;
            this.imageResForEmptyUri = 0;
            this.imageResOnFail = 0;
            this.imageOnLoading = null;
            this.imageForEmptyUri = null;
            this.imageOnFail = null;
            this.resetViewBeforeLoading = false;
            this.cacheInMemory = false;
            this.cacheOnDisk = false;
            this.imageScaleType = ImageScaleType.IN_SAMPLE_POWER_OF_2;
            this.decodingOptions = new Options();
            this.delayBeforeLoading = 0;
            this.considerExifParams = false;
            this.extraForDownloader = null;
            this.preProcessor = null;
            this.postProcessor = null;
            this.displayer = DefaultConfigurationFactory.createBitmapDisplayer();
            this.handler = null;
            this.isSyncLoading = false;
            this.decodingOptions.inPurgeable = true;
            this.decodingOptions.inInputShareable = true;
        }

        @Deprecated
        public Builder showStubImage(int imageRes) {
            this.imageResOnLoading = imageRes;
            return this;
        }

        public Builder showImageOnLoading(int imageRes) {
            this.imageResOnLoading = imageRes;
            return this;
        }

        public Builder showImageOnLoading(Drawable drawable) {
            this.imageOnLoading = drawable;
            return this;
        }

        public Builder showImageForEmptyUri(int imageRes) {
            this.imageResForEmptyUri = imageRes;
            return this;
        }

        public Builder showImageForEmptyUri(Drawable drawable) {
            this.imageForEmptyUri = drawable;
            return this;
        }

        public Builder showImageOnFail(int imageRes) {
            this.imageResOnFail = imageRes;
            return this;
        }

        public Builder showImageOnFail(Drawable drawable) {
            this.imageOnFail = drawable;
            return this;
        }

        public Builder resetViewBeforeLoading() {
            this.resetViewBeforeLoading = true;
            return this;
        }

        public Builder resetViewBeforeLoading(boolean resetViewBeforeLoading2) {
            this.resetViewBeforeLoading = resetViewBeforeLoading2;
            return this;
        }

        @Deprecated
        public Builder cacheInMemory() {
            this.cacheInMemory = true;
            return this;
        }

        public Builder cacheInMemory(boolean cacheInMemory2) {
            this.cacheInMemory = cacheInMemory2;
            return this;
        }

        @Deprecated
        public Builder cacheOnDisc() {
            return cacheOnDisk(true);
        }

        @Deprecated
        public Builder cacheOnDisc(boolean cacheOnDisk2) {
            return cacheOnDisk(cacheOnDisk2);
        }

        public Builder cacheOnDisk(boolean cacheOnDisk2) {
            this.cacheOnDisk = cacheOnDisk2;
            return this;
        }

        public Builder imageScaleType(ImageScaleType imageScaleType2) {
            this.imageScaleType = imageScaleType2;
            return this;
        }

        public Builder bitmapConfig(Config bitmapConfig) {
            if (bitmapConfig == null) {
                throw new IllegalArgumentException("bitmapConfig can't be null");
            }
            this.decodingOptions.inPreferredConfig = bitmapConfig;
            return this;
        }

        public Builder decodingOptions(Options decodingOptions2) {
            if (decodingOptions2 == null) {
                throw new IllegalArgumentException("decodingOptions can't be null");
            }
            this.decodingOptions = decodingOptions2;
            return this;
        }

        public Builder delayBeforeLoading(int delayInMillis) {
            this.delayBeforeLoading = delayInMillis;
            return this;
        }

        public Builder extraForDownloader(Object extra) {
            this.extraForDownloader = extra;
            return this;
        }

        public Builder considerExifParams(boolean considerExifParams2) {
            this.considerExifParams = considerExifParams2;
            return this;
        }

        public Builder preProcessor(BitmapProcessor preProcessor2) {
            this.preProcessor = preProcessor2;
            return this;
        }

        public Builder postProcessor(BitmapProcessor postProcessor2) {
            this.postProcessor = postProcessor2;
            return this;
        }

        public Builder displayer(BitmapDisplayer displayer2) {
            if (displayer2 == null) {
                throw new IllegalArgumentException("displayer can't be null");
            }
            this.displayer = displayer2;
            return this;
        }

        /* access modifiers changed from: 0000 */
        public Builder syncLoading(boolean isSyncLoading2) {
            this.isSyncLoading = isSyncLoading2;
            return this;
        }

        public Builder handler(Handler handler2) {
            this.handler = handler2;
            return this;
        }

        public Builder cloneFrom(DisplayImageOptions options) {
            this.imageResOnLoading = options.imageResOnLoading;
            this.imageResForEmptyUri = options.imageResForEmptyUri;
            this.imageResOnFail = options.imageResOnFail;
            this.imageOnLoading = options.imageOnLoading;
            this.imageForEmptyUri = options.imageForEmptyUri;
            this.imageOnFail = options.imageOnFail;
            this.resetViewBeforeLoading = options.resetViewBeforeLoading;
            this.cacheInMemory = options.cacheInMemory;
            this.cacheOnDisk = options.cacheOnDisk;
            this.imageScaleType = options.imageScaleType;
            this.decodingOptions = options.decodingOptions;
            this.delayBeforeLoading = options.delayBeforeLoading;
            this.considerExifParams = options.considerExifParams;
            this.extraForDownloader = options.extraForDownloader;
            this.preProcessor = options.preProcessor;
            this.postProcessor = options.postProcessor;
            this.displayer = options.displayer;
            this.handler = options.handler;
            this.isSyncLoading = options.isSyncLoading;
            return this;
        }

        public DisplayImageOptions build() {
            return new DisplayImageOptions(this);
        }
    }

    private DisplayImageOptions(Builder builder) {
        this.imageResOnLoading = builder.imageResOnLoading;
        this.imageResForEmptyUri = builder.imageResForEmptyUri;
        this.imageResOnFail = builder.imageResOnFail;
        this.imageOnLoading = builder.imageOnLoading;
        this.imageForEmptyUri = builder.imageForEmptyUri;
        this.imageOnFail = builder.imageOnFail;
        this.resetViewBeforeLoading = builder.resetViewBeforeLoading;
        this.cacheInMemory = builder.cacheInMemory;
        this.cacheOnDisk = builder.cacheOnDisk;
        this.imageScaleType = builder.imageScaleType;
        this.decodingOptions = builder.decodingOptions;
        this.delayBeforeLoading = builder.delayBeforeLoading;
        this.considerExifParams = builder.considerExifParams;
        this.extraForDownloader = builder.extraForDownloader;
        this.preProcessor = builder.preProcessor;
        this.postProcessor = builder.postProcessor;
        this.displayer = builder.displayer;
        this.handler = builder.handler;
        this.isSyncLoading = builder.isSyncLoading;
    }

    public boolean shouldShowImageOnLoading() {
        return (this.imageOnLoading == null && this.imageResOnLoading == 0) ? false : true;
    }

    public boolean shouldShowImageForEmptyUri() {
        return (this.imageForEmptyUri == null && this.imageResForEmptyUri == 0) ? false : true;
    }

    public boolean shouldShowImageOnFail() {
        return (this.imageOnFail == null && this.imageResOnFail == 0) ? false : true;
    }

    public boolean shouldPreProcess() {
        return this.preProcessor != null;
    }

    public boolean shouldPostProcess() {
        return this.postProcessor != null;
    }

    public boolean shouldDelayBeforeLoading() {
        return this.delayBeforeLoading > 0;
    }

    public Drawable getImageOnLoading(Resources res) {
        return this.imageResOnLoading != 0 ? res.getDrawable(this.imageResOnLoading) : this.imageOnLoading;
    }

    public Drawable getImageForEmptyUri(Resources res) {
        return this.imageResForEmptyUri != 0 ? res.getDrawable(this.imageResForEmptyUri) : this.imageForEmptyUri;
    }

    public Drawable getImageOnFail(Resources res) {
        return this.imageResOnFail != 0 ? res.getDrawable(this.imageResOnFail) : this.imageOnFail;
    }

    public boolean isResetViewBeforeLoading() {
        return this.resetViewBeforeLoading;
    }

    public boolean isCacheInMemory() {
        return this.cacheInMemory;
    }

    public boolean isCacheOnDisk() {
        return this.cacheOnDisk;
    }

    public ImageScaleType getImageScaleType() {
        return this.imageScaleType;
    }

    public Options getDecodingOptions() {
        return this.decodingOptions;
    }

    public int getDelayBeforeLoading() {
        return this.delayBeforeLoading;
    }

    public boolean isConsiderExifParams() {
        return this.considerExifParams;
    }

    public Object getExtraForDownloader() {
        return this.extraForDownloader;
    }

    public BitmapProcessor getPreProcessor() {
        return this.preProcessor;
    }

    public BitmapProcessor getPostProcessor() {
        return this.postProcessor;
    }

    public BitmapDisplayer getDisplayer() {
        return this.displayer;
    }

    public Handler getHandler() {
        return this.handler;
    }

    /* access modifiers changed from: 0000 */
    public boolean isSyncLoading() {
        return this.isSyncLoading;
    }

    public static DisplayImageOptions createSimple() {
        return new Builder().build();
    }
}