package com.nuvent.shareat.util.crop;

import android.net.Uri;
import java.util.HashMap;

public interface IImageList {
    void close();

    HashMap<String, String> getBucketIds();

    int getCount();

    IImage getImageAt(int i);

    IImage getImageForUri(Uri uri);

    int getImageIndex(IImage iImage);

    boolean isEmpty();

    boolean removeImage(IImage iImage);

    boolean removeImageAt(int i);
}