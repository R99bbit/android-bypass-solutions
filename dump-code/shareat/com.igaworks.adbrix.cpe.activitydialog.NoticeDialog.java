package com.igaworks.adbrix.cpe.activitydialog;

import android.app.Activity;
import android.content.Context;
import android.content.res.Configuration;
import android.graphics.Bitmap;
import android.graphics.Bitmap.CompressFormat;
import android.graphics.BitmapFactory;
import android.graphics.drawable.shapes.RoundRectShape;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.webkit.WebView;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.ProgressBar;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.cpe.CPECompletionHandler;
import com.igaworks.adbrix.cpe.common.CustomShapeDrawable;
import com.igaworks.adbrix.db.ConversionDAOForRetryCompletion;
import com.igaworks.adbrix.util.SizeAwareImageView;
import com.igaworks.core.DisplaySetter;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.InternalAction;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import com.igaworks.util.image.ImageCacheFactory;
import com.igaworks.util.image.ImageDownloadAsyncCallback;
import com.kakao.kakaolink.internal.KakaoTalkLinkProtocol;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.Executor;

public class NoticeDialog extends Activity {
    public static final String CLICK_ACTION_CLOSE = "no";
    public static final String CLICK_ACTION_URL = "url";
    public static final String TYPE_IMAGE = "image";
    public static final String TYPE_WEB = "web";
    private String clickAction;
    /* access modifiers changed from: private */
    public ImageView closeBtnIv;
    /* access modifiers changed from: private */
    public int conversionKey;
    /* access modifiers changed from: private */
    public SizeAwareImageView imageView;
    /* access modifiers changed from: private */
    public FrameLayout imageViewParent;
    private Bitmap img;
    public OnClickListener landingClickActionListener = new OnClickListener() {
        public void onClick(View v) {
            NoticeDialog.this.webview = new WebView(NoticeDialog.this);
            NoticeDialog.this.webviewParam = new LayoutParams(-2, -2);
            NoticeDialog.this.webview.setVerticalScrollBarEnabled(false);
            NoticeDialog.this.webview.setHorizontalScrollBarEnabled(false);
            NoticeDialog.this.webview.setBackgroundColor(-1);
            NoticeDialog.this.webview.loadUrl(NoticeDialog.this.landing_url);
        }
    };
    /* access modifiers changed from: private */
    public String landing_url;
    public OnClickListener noClickActionListener = new OnClickListener() {
        public void onClick(View v) {
            NoticeDialog.this.finish();
        }
    };
    /* access modifiers changed from: private */
    public LayoutParams parentParam;
    /* access modifiers changed from: private */
    public FrameLayout progressCircle;
    private String type;
    /* access modifiers changed from: private */
    public String url;
    private LinearLayout webViewParent;
    /* access modifiers changed from: private */
    public WebView webview;
    /* access modifiers changed from: private */
    public LayoutParams webviewParam;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        this.url = getIntent().getStringExtra("noti_url");
        if (getIntent().hasExtra(KakaoTalkLinkProtocol.ACTION_TYPE)) {
            this.type = getIntent().getStringExtra(KakaoTalkLinkProtocol.ACTION_TYPE);
        }
        if (this.type == null) {
            this.type = "image";
        }
        if (getIntent().hasExtra("click_action")) {
            this.clickAction = getIntent().getStringExtra("click_action");
        }
        if (this.clickAction == null) {
            this.clickAction = "no";
        }
        if (getIntent().hasExtra("conversion_key")) {
            this.conversionKey = getIntent().getIntExtra("conversion_key", 0);
        }
        if (getIntent().hasExtra("landing_url")) {
            this.landing_url = getIntent().getStringExtra("landing_url");
        }
        IgawLogger.Logging(this, IgawConstant.QA_TAG, String.format("img_url = %s, type = %s, click_action = %s, landing_url = %s", new Object[]{this.url, this.type, this.clickAction, this.landing_url}), 3, false);
        requestWindowFeature(1);
        WindowManager.LayoutParams lpWindow = getWindow().getAttributes();
        lpWindow.flags = 2;
        lpWindow.dimAmount = 0.6f;
        lpWindow.width = -1;
        lpWindow.height = -1;
        getWindow().setAttributes(lpWindow);
        getWindow().setSoftInputMode(16);
        getWindow().getDecorView().setBackgroundColor(0);
        getWindow().getDecorView().setPadding(30, 30, 30, 30);
        if (this.type.equals("web")) {
            if (!this.clickAction.equals("url") || this.landing_url == null) {
                setLayoutWebView(this.noClickActionListener);
            } else {
                setLayoutWebView(this.landingClickActionListener);
            }
        } else if (!this.type.equals("image")) {
        } else {
            if (!this.clickAction.equals("url") || this.landing_url == null) {
                setLayoutImageView(this.noClickActionListener);
            } else {
                setLayoutImageView(this.landingClickActionListener);
            }
        }
    }

    private void setLayoutWebView(OnClickListener clickAction2) {
        new CustomShapeDrawable(new RoundRectShape(new float[]{20.0f, 20.0f, 20.0f, 20.0f, 20.0f, 20.0f, 20.0f, 20.0f}, null, null), -1, -1, 20);
        this.webViewParent = new LinearLayout(this);
        this.parentParam = new LayoutParams(-1, -1);
        this.webViewParent.setBackgroundColor(0);
        this.webViewParent.setLayoutParams(this.parentParam);
        this.webViewParent.setPadding(20, 20, 20, 20);
        this.webViewParent.setOnClickListener(clickAction2);
        this.webview = new WebView(this);
        this.webviewParam = new LayoutParams(-1, -1);
        this.webview.setLayoutParams(this.webviewParam);
        this.webview.setVerticalScrollBarEnabled(false);
        this.webview.setHorizontalScrollBarEnabled(false);
        this.webview.getSettings().setJavaScriptCanOpenWindowsAutomatically(true);
        this.webview.setBackgroundColor(-1);
        this.webview.loadUrl(this.url);
        this.webViewParent.addView(this.webview);
        addContentView(this.webViewParent, this.parentParam);
    }

    private void setLayoutImageView(OnClickListener clickAction2) {
        this.imageViewParent = new FrameLayout(this);
        this.parentParam = new LayoutParams(-1, -1);
        this.imageViewParent.setBackgroundColor(0);
        this.imageView = new SizeAwareImageView(this);
        int margin = (int) (10.0f * DisplaySetter.getNormalizeFactor(this));
        FrameLayout.LayoutParams webviewParam2 = new FrameLayout.LayoutParams(-1, -1, 17);
        webviewParam2.topMargin = margin;
        webviewParam2.bottomMargin = margin;
        webviewParam2.leftMargin = margin;
        webviewParam2.rightMargin = margin;
        this.imageView.setLayoutParams(webviewParam2);
        this.imageView.setScaleType(ScaleType.FIT_CENTER);
        this.imageView.setOnClickListener(clickAction2);
        addProgressCircle(this, this.imageViewParent);
        if (CommonHelper.CheckPermissionForCommonSDK(this)) {
            CPECompletionHandler.getImageDownloader(this).download(this.url, null, null, this.progressCircle, new ImageDownloadAsyncCallback(this.url, null, ImageCacheFactory.getInstance().get("imagecache"), this.progressCircle) {
                public void onResultCustom(Bitmap bitmap) {
                    if (!(NoticeDialog.this.progressCircle == null || NoticeDialog.this.progressCircle.getParent() == null)) {
                        ((ViewGroup) NoticeDialog.this.progressCircle.getParent()).removeView(NoticeDialog.this.progressCircle);
                    }
                    if (bitmap == null) {
                        if (NoticeDialog.this.conversionKey != 0) {
                            Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
                                public Void then(Task<Object> task) throws Exception {
                                    ConversionDAOForRetryCompletion.getDAO(NoticeDialog.this.getApplicationContext()).updateOrInsertConversionForRetry(NoticeDialog.this.conversionKey);
                                    IgawLogger.Logging(NoticeDialog.this.getApplicationContext(), IgawConstant.QA_TAG, "Notice Dialog > image downloader returned null, add to restore storage", 3, false);
                                    return null;
                                }
                            }, (Executor) Task.BACKGROUND_EXECUTOR);
                        }
                        NoticeDialog.this.finish();
                        return;
                    }
                    NoticeDialog.this.imageView.setImageBitmap(bitmap);
                    NoticeDialog.this.imageViewParent.addView(NoticeDialog.this.imageView);
                    NoticeDialog.this.addContentView(NoticeDialog.this.imageViewParent, NoticeDialog.this.parentParam);
                    NoticeDialog.this.imageView.postDelayed(new Runnable() {
                        public void run() {
                            NoticeDialog.this.closeBtnIv = new ImageView(NoticeDialog.this);
                            int size = (int) (20.0f * DisplaySetter.getNormalizeFactor(NoticeDialog.this));
                            FrameLayout.LayoutParams closeBtnParam = new FrameLayout.LayoutParams(size, size, 53);
                            int[] closeBtnMargin = new int[2];
                            NoticeDialog.this.imageView.getLocationInWindow(closeBtnMargin);
                            Configuration config = NoticeDialog.this.getResources().getConfiguration();
                            IgawLogger.Logging(NoticeDialog.this.getApplicationContext(), IgawConstant.QA_TAG, String.format("screen width/height : %d/%d, imageView width/height : %d/%d, imageViewPoistion : %d/%d", new Object[]{Integer.valueOf(DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).widthPixels), Integer.valueOf(DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).heightPixels), Integer.valueOf(NoticeDialog.this.imageView.getActualWidth()), Integer.valueOf(NoticeDialog.this.imageView.getActualHeight()), Integer.valueOf(closeBtnMargin[0]), Integer.valueOf(closeBtnMargin[1])}), 3);
                            if (config.orientation == 2) {
                                closeBtnParam.rightMargin = ((Math.max(DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).widthPixels, DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).heightPixels) - NoticeDialog.this.imageView.getActualWidth()) / 2) - closeBtnMargin[0];
                            } else {
                                closeBtnParam.topMargin = (((Math.max(DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).widthPixels, DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).heightPixels) - NoticeDialog.this.imageView.getActualHeight()) / 2) - closeBtnMargin[1]) + (size / 2);
                            }
                            NoticeDialog.this.closeBtnIv.setLayoutParams(closeBtnParam);
                            NoticeDialog.this.closeBtnIv.setOnClickListener(new OnClickListener() {
                                public void onClick(View v) {
                                    NoticeDialog.this.finish();
                                }
                            });
                            CPECompletionHandler.getImageDownloader(NoticeDialog.this).download(ADBrixHttpManager.schedule.getSchedule().getMedia().getTheme().getCloseBtn(), null, null, NoticeDialog.this.progressCircle, new ImageDownloadAsyncCallback(ADBrixHttpManager.schedule.getSchedule().getMedia().getTheme().getCloseBtn(), null, ImageCacheFactory.getInstance().get("imagecache"), NoticeDialog.this.progressCircle) {
                                public void onResultCustom(Bitmap bitmap) {
                                    NoticeDialog.this.closeBtnIv.setImageBitmap(bitmap);
                                    NoticeDialog.this.imageViewParent.addView(NoticeDialog.this.closeBtnIv);
                                    NoticeDialog.this.imageView.getLayoutParams().width = NoticeDialog.this.imageView.getActualWidth();
                                    NoticeDialog.this.imageView.getLayoutParams().height = NoticeDialog.this.imageView.getActualHeight();
                                }
                            });
                        }
                    }, 500);
                }
            });
            return;
        }
        InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
            public void run() {
                final Bitmap bitmap = CommonHelper.getBitmapFromURL(NoticeDialog.this.url);
                new Handler(NoticeDialog.this.getMainLooper()).post(new Runnable() {
                    public void run() {
                        if (!(NoticeDialog.this.progressCircle == null || NoticeDialog.this.progressCircle.getParent() == null)) {
                            ((ViewGroup) NoticeDialog.this.progressCircle.getParent()).removeView(NoticeDialog.this.progressCircle);
                        }
                        if (bitmap == null) {
                            if (NoticeDialog.this.conversionKey != 0) {
                                Task.forResult(null).continueWith((Continuation<TResult, TContinuationResult>) new Continuation<Object, Void>() {
                                    public Void then(Task<Object> task) throws Exception {
                                        ConversionDAOForRetryCompletion.getDAO(NoticeDialog.this.getApplicationContext()).updateOrInsertConversionForRetry(NoticeDialog.this.conversionKey);
                                        IgawLogger.Logging(NoticeDialog.this.getApplicationContext(), IgawConstant.QA_TAG, "Notice Dialog > image downloader returned null, add to restore storage", 3, false);
                                        return null;
                                    }
                                }, (Executor) Task.BACKGROUND_EXECUTOR);
                            }
                            NoticeDialog.this.finish();
                            return;
                        }
                        NoticeDialog.this.imageView.setImageBitmap(bitmap);
                        NoticeDialog.this.imageViewParent.addView(NoticeDialog.this.imageView);
                        NoticeDialog.this.addContentView(NoticeDialog.this.imageViewParent, NoticeDialog.this.parentParam);
                        NoticeDialog.this.imageView.postDelayed(new Runnable() {
                            public void run() {
                                NoticeDialog.this.closeBtnIv = new ImageView(NoticeDialog.this);
                                int size = (int) (20.0f * DisplaySetter.getNormalizeFactor(NoticeDialog.this));
                                FrameLayout.LayoutParams closeBtnParam = new FrameLayout.LayoutParams(size, size, 53);
                                int[] closeBtnMargin = new int[2];
                                NoticeDialog.this.imageView.getLocationInWindow(closeBtnMargin);
                                Configuration config = NoticeDialog.this.getResources().getConfiguration();
                                IgawLogger.Logging(NoticeDialog.this.getApplicationContext(), IgawConstant.QA_TAG, String.format("screen width/height : %d/%d, imageView width/height : %d/%d, imageViewPoistion : %d/%d", new Object[]{Integer.valueOf(DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).widthPixels), Integer.valueOf(DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).heightPixels), Integer.valueOf(NoticeDialog.this.imageView.getActualWidth()), Integer.valueOf(NoticeDialog.this.imageView.getActualHeight()), Integer.valueOf(closeBtnMargin[0]), Integer.valueOf(closeBtnMargin[1])}), 3);
                                if (config.orientation == 2) {
                                    closeBtnParam.rightMargin = ((Math.max(DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).widthPixels, DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).heightPixels) - NoticeDialog.this.imageView.getActualWidth()) / 2) - closeBtnMargin[0];
                                } else {
                                    closeBtnParam.topMargin = (((Math.max(DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).widthPixels, DisplaySetter.getDisplayXY(NoticeDialog.this.getApplicationContext()).heightPixels) - NoticeDialog.this.imageView.getActualHeight()) / 2) - closeBtnMargin[1]) + (size / 2);
                                }
                                NoticeDialog.this.closeBtnIv.setLayoutParams(closeBtnParam);
                                NoticeDialog.this.closeBtnIv.setOnClickListener(new OnClickListener() {
                                    public void onClick(View v) {
                                        NoticeDialog.this.finish();
                                    }
                                });
                                InternalAction.NETWORK_EXECUTOR.execute(new Runnable() {
                                    public void run() {
                                        final Bitmap bitmap = CommonHelper.getBitmapFromURL(ADBrixHttpManager.schedule.getSchedule().getMedia().getTheme().getCloseBtn());
                                        new Handler(NoticeDialog.this.getMainLooper()).post(new Runnable() {
                                            public void run() {
                                                try {
                                                    NoticeDialog.this.closeBtnIv.setImageBitmap(bitmap);
                                                    NoticeDialog.this.imageViewParent.addView(NoticeDialog.this.closeBtnIv);
                                                    NoticeDialog.this.imageView.getLayoutParams().width = NoticeDialog.this.imageView.getActualWidth();
                                                    NoticeDialog.this.imageView.getLayoutParams().height = NoticeDialog.this.imageView.getActualHeight();
                                                } catch (Exception e) {
                                                    e.printStackTrace();
                                                }
                                            }
                                        });
                                    }
                                });
                            }
                        }, 500);
                    }
                });
            }
        });
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        if (this.img != null) {
            try {
                this.img.recycle();
            } catch (Exception e) {
            }
        }
    }

    public static Bitmap getBitmapFromURL(String link) {
        try {
            HttpURLConnection connection = (HttpURLConnection) new URL(link).openConnection();
            connection.setDoInput(true);
            connection.connect();
            return BitmapFactory.decodeStream(connection.getInputStream());
        } catch (IOException e) {
            return null;
        }
    }

    public static void saveImageFile(String url2) {
        String fileName = CPECompletionHandler.computeHashedName(url2);
        Bitmap bitmap = getBitmapFromURL(url2);
        File mFile1 = new File(new StringBuilder(String.valueOf(Environment.getExternalStorageDirectory().getAbsolutePath())).append("/adbrix/").toString());
        if (!mFile1.exists()) {
            mFile1.mkdirs();
        }
        File mFile2 = new File(mFile1, fileName);
        if (!mFile2.exists()) {
            try {
                FileOutputStream outStream = new FileOutputStream(mFile2);
                bitmap.compress(CompressFormat.PNG, 100, outStream);
                outStream.flush();
                outStream.close();
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            } catch (IOException e2) {
                e2.printStackTrace();
            }
        }
    }

    private void addProgressCircle(Context context, ViewGroup parent) {
        try {
            this.progressCircle = new FrameLayout(context);
            ProgressBar progressCirclePb = new ProgressBar(context);
            LayoutParams pcParam = new LayoutParams(-1, -1);
            FrameLayout.LayoutParams pcpbParam = new FrameLayout.LayoutParams(-2, -2);
            pcpbParam.gravity = 17;
            pcParam.gravity = 17;
            progressCirclePb.setLayoutParams(pcpbParam);
            this.progressCircle.setLayoutParams(pcParam);
            this.progressCircle.addView(progressCirclePb);
            this.imageViewParent.addView(this.progressCircle);
        } catch (Exception e) {
        }
    }
}