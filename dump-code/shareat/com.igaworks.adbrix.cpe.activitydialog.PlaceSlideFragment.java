package com.igaworks.adbrix.cpe.activitydialog;

import android.content.Intent;
import android.graphics.Bitmap;
import android.os.Bundle;
import android.os.Handler;
import android.support.v4.app.Fragment;
import android.support.v4.view.ViewCompat;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import com.igaworks.adbrix.cpe.CPECompletionHandler;
import com.igaworks.adbrix.util.CPEConstant;
import com.igaworks.impl.InternalAction;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.image.ImageCacheFactory;
import com.igaworks.util.image.ImageDownloadAsyncCallback;

public final class PlaceSlideFragment extends Fragment {
    /* access modifiers changed from: private */
    public int campaignKey;
    /* access modifiers changed from: private */
    public String imageUrl;
    private boolean isFullScreen = false;
    /* access modifiers changed from: private */
    public int position;

    public static PlaceSlideFragment newInstance(String imageUrl2, int campaignKey2, int position2, boolean isFullScreen2) {
        PlaceSlideFragment psf = new PlaceSlideFragment();
        Bundle bundle = new Bundle();
        bundle.putString("imageUrl", imageUrl2);
        bundle.putInt("campaignKey", campaignKey2);
        bundle.putInt("position", position2);
        bundle.putBoolean("isFullScreen", isFullScreen2);
        psf.setArguments(bundle);
        return psf;
    }

    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.imageUrl = getArguments().getString("imageUrl");
        this.campaignKey = getArguments().getInt("campaignKey");
        this.position = getArguments().getInt("position");
        this.isFullScreen = getArguments().getBoolean("isFullScreen", false);
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        LinearLayout layout = new LinearLayout(getActivity());
        layout.setLayoutParams(new LayoutParams(-1, -1));
        final ImageView image = new ImageView(getActivity());
        LayoutParams imageParam = new LayoutParams(-1, -1);
        ScaleType scale = ScaleType.FIT_XY;
        if (this.isFullScreen) {
            scale = ScaleType.FIT_CENTER;
        }
        try {
            image.setScaleType(scale);
            image.setLayoutParams(imageParam);
            int borderWidth = CPEConstant.convertPixelToDP(getActivity(), 1, true);
            image.setPadding(borderWidth, borderWidth, borderWidth, borderWidth);
            image.setBackgroundColor(ViewCompat.MEASURED_STATE_MASK);
            if (CommonHelper.CheckPermissionForCommonSDK(getActivity())) {
                final ImageView imageView = image;
                CPECompletionHandler.getImageDownloader(getActivity()).download(this.imageUrl, image, null, null, new ImageDownloadAsyncCallback(this.imageUrl, image, ImageCacheFactory.getInstance().get("imagecache"), null) {
                    public void onResultCustom(Bitmap bitmap) {
                        try {
                            if (PlaceDetailsFragment.pdFragment != null) {
                                PlaceDetailsFragment.pdFragment.addUsingBitmap(bitmap);
                            }
                            imageView.setImageBitmap(bitmap);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
            } else {
                InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                    public void run() {
                        final Bitmap bitmap = CommonHelper.getBitmapFromURL(PlaceSlideFragment.this.imageUrl);
                        Handler handler = new Handler(PlaceSlideFragment.this.getActivity().getMainLooper());
                        final ImageView imageView = image;
                        handler.post(new Runnable() {
                            public void run() {
                                try {
                                    if (PlaceDetailsFragment.pdFragment != null) {
                                        PlaceDetailsFragment.pdFragment.addUsingBitmap(bitmap);
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
            if (!this.isFullScreen) {
                image.setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        try {
                            Intent i = new Intent(PlaceSlideFragment.this.getActivity(), FullScreenSlider.class);
                            i.putExtra("campaignKey", PlaceSlideFragment.this.campaignKey);
                            i.putExtra("position", PlaceSlideFragment.this.position);
                            PlaceSlideFragment.this.startActivity(i);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
            } else {
                image.setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        try {
                            if (FullScreenSlider.slider != null) {
                                FullScreenSlider.slider.finish();
                            }
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                });
            }
            layout.setGravity(17);
            layout.addView(image);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return layout;
    }

    public void onDestroyView() {
        super.onDestroyView();
    }
}