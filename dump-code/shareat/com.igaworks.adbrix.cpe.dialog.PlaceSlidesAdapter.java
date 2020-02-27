package com.igaworks.adbrix.cpe.dialog;

import android.app.Activity;
import android.graphics.Bitmap;
import android.os.Handler;
import android.os.Parcelable;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.ViewCompat;
import android.support.v4.view.ViewPager;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup.LayoutParams;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import com.igaworks.adbrix.cpe.CPECompletionHandler;
import com.igaworks.adbrix.cpe.common.IconPagerAdapter;
import com.igaworks.adbrix.util.CPEConstant;
import com.igaworks.impl.InternalAction;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.image.ImageCacheFactory;
import com.igaworks.util.image.ImageDownloadAsyncCallback;
import java.util.List;

public class PlaceSlidesAdapter extends PagerAdapter implements IconPagerAdapter {
    /* access modifiers changed from: private */
    public Activity activity;
    /* access modifiers changed from: private */
    public int campaignKey;
    /* access modifiers changed from: private */
    public List<String> imageUrlList;
    private boolean isFullscreen;

    public PlaceSlidesAdapter(Activity activity2, List<String> imageUrlList2, int campaignKey2, boolean isFullscreen2) {
        this.imageUrlList = imageUrlList2;
        this.activity = activity2;
        this.isFullscreen = isFullscreen2;
        this.campaignKey = campaignKey2;
    }

    public int getCount() {
        return this.imageUrlList.size();
    }

    public Object instantiateItem(View collection, int position) {
        final ImageView view = new ImageView(this.activity);
        view.setLayoutParams(new LayoutParams(-1, -1));
        int borderWidth = CPEConstant.convertPixelToDP(this.activity, 1, true);
        view.setPadding(borderWidth, borderWidth, borderWidth, borderWidth);
        view.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
        if (CommonHelper.CheckPermissionForCommonSDK(this.activity)) {
            CPECompletionHandler.getImageDownloader(this.activity).download(this.imageUrlList.get(position), null, null, null, new ImageDownloadAsyncCallback(this.imageUrlList.get(position), null, ImageCacheFactory.getInstance().get("imagecache"), null) {
                public void onResultCustom(Bitmap bitmap) {
                    if (PlaceDetailsLayout.pdLayout != null) {
                        PlaceDetailsLayout.pdLayout.addUsingBitmap(bitmap);
                    }
                    view.setImageBitmap(bitmap);
                }
            });
        } else {
            final int i = position;
            InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                public void run() {
                    final Bitmap bitmap = CommonHelper.getBitmapFromURL((String) PlaceSlidesAdapter.this.imageUrlList.get(i));
                    Handler handler = new Handler(PlaceSlidesAdapter.this.activity.getMainLooper());
                    final ImageView imageView = view;
                    handler.post(new Runnable() {
                        public void run() {
                            try {
                                if (PlaceDetailsLayout.pdLayout != null) {
                                    PlaceDetailsLayout.pdLayout.addUsingBitmap(bitmap);
                                }
                                imageView.setImageBitmap(bitmap);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                    });
                }
            });
        }
        ((ViewPager) collection).addView(view, 0);
        if (this.isFullscreen) {
            view.setScaleType(ScaleType.FIT_CENTER);
            view.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    if (FullScreenSlider.slider != null) {
                        FullScreenSlider.slider.dismiss();
                    }
                }
            });
        } else {
            view.setScaleType(ScaleType.FIT_XY);
            view.setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    new FullScreenSlider(PlaceSlidesAdapter.this.activity, PlaceSlidesAdapter.this.activity, PlaceSlidesAdapter.this.campaignKey, 0).show();
                }
            });
        }
        return view;
    }

    public void destroyItem(View arg0, int arg1, Object arg2) {
        ((ViewPager) arg0).removeView((View) arg2);
    }

    public boolean isViewFromObject(View arg0, Object arg1) {
        return arg0 == ((View) arg1);
    }

    public Parcelable saveState() {
        return null;
    }
}