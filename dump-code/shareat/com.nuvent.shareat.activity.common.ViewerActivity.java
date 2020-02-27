package com.nuvent.shareat.activity.common;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.os.Environment;
import android.support.v4.view.PagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
import com.nostra13.universalimageloader.core.ImageLoader;
import com.nostra13.universalimageloader.core.assist.FailReason;
import com.nostra13.universalimageloader.core.listener.ImageLoadingListener;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.crop.CropActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.store.StoreAllImageListApi;
import com.nuvent.shareat.api.store.StoreReviewApi;
import com.nuvent.shareat.event.ImageClickEvent;
import com.nuvent.shareat.event.ImageListEvent;
import com.nuvent.shareat.model.InstagramModel;
import com.nuvent.shareat.model.store.ReviewInfoResultModel;
import com.nuvent.shareat.model.store.StoreAllImageModel;
import com.nuvent.shareat.model.store.StoreAllImageResultModel;
import com.nuvent.shareat.model.store.StoreDetailModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.util.crop.CropImageIntentBuilder;
import de.greenrobot.event.EventBus;
import java.io.File;
import java.util.ArrayList;
import net.xenix.util.ImageDisplay;

public class ViewerActivity extends BaseActivity {
    private static final int IMAGE_ITEM_LIMIT_COUNT = 10;
    private static final int VIEWER_TYPE_REVIEW = 2;
    private static final int VIEWER_TYPE_STORE = 1;
    /* access modifiers changed from: private */
    public TouchImageAdapter mAdapter;
    private String mFeedSno;
    private StoreDetailModel mModel;
    /* access modifiers changed from: private */
    public ArrayList<StoreAllImageModel> mModels;
    private String mPartnerSno;
    /* access modifiers changed from: private */
    public ReviewInfoResultModel mReviewModel;
    /* access modifiers changed from: private */
    public int mTotalCount = 0;
    /* access modifiers changed from: private */
    public int mViewerType = 1;
    /* access modifiers changed from: private */
    public OnClickImage onClickImageViewListener = new OnClickImage() {
        public void onClickImageView() {
            if (ViewerActivity.this.findViewById(R.id.titleLayout).getVisibility() != 0) {
                ViewerActivity.this.findViewById(R.id.titleLayout).startAnimation(AnimationUtils.loadAnimation(ViewerActivity.this, R.anim.abc_slide_in_top));
                ViewerActivity.this.findViewById(R.id.titleLayout).setVisibility(0);
                ViewerActivity.this.findViewById(R.id.contentsLayout).startAnimation(AnimationUtils.loadAnimation(ViewerActivity.this, R.anim.abc_slide_in_bottom));
                ViewerActivity.this.findViewById(R.id.contentsLayout).setVisibility(0);
                return;
            }
            ViewerActivity.this.findViewById(R.id.titleLayout).startAnimation(AnimationUtils.loadAnimation(ViewerActivity.this, R.anim.abc_slide_out_top));
            ViewerActivity.this.findViewById(R.id.titleLayout).setVisibility(8);
            ViewerActivity.this.findViewById(R.id.contentsLayout).startAnimation(AnimationUtils.loadAnimation(ViewerActivity.this, R.anim.abc_slide_out_bottom));
            ViewerActivity.this.findViewById(R.id.contentsLayout).setVisibility(8);
        }
    };

    private static class TouchImageAdapter extends PagerAdapter {
        private Context mContext;
        private LayoutInflater mLayoutInflater;
        /* access modifiers changed from: private */
        public OnClickImage mListener;
        private ArrayList<StoreAllImageModel> mModels;
        private ReviewInfoResultModel mReviewModel;
        private int mViewerType;

        public interface OnClickImage {
            void onClickImageView();
        }

        private TouchImageAdapter(Context context, ArrayList<StoreAllImageModel> models) {
            this.mModels = new ArrayList<>();
            this.mViewerType = 1;
            this.mModels = models;
            this.mContext = context;
            this.mLayoutInflater = (LayoutInflater) context.getSystemService("layout_inflater");
        }

        private TouchImageAdapter(Context context, ReviewInfoResultModel reviewModel, int type) {
            this.mModels = new ArrayList<>();
            this.mViewerType = 1;
            this.mViewerType = type;
            this.mReviewModel = reviewModel;
            this.mContext = context;
            this.mLayoutInflater = (LayoutInflater) context.getSystemService("layout_inflater");
        }

        public int getItemPosition(Object object) {
            return -2;
        }

        public int getCount() {
            if (this.mViewerType == 1) {
                return this.mModels.size();
            }
            return this.mReviewModel.getImg_list().size();
        }

        public View instantiateItem(ViewGroup container, int position) {
            View view = this.mLayoutInflater.inflate(R.layout.view_album_viewer, null);
            if (this.mViewerType == 1) {
                ImageDisplay.getInstance().displayImageLoad(this.mModels.get(position).img_real.isEmpty() ? this.mModels.get(position).img_url : this.mModels.get(position).img_real, (ImageView) view.findViewById(R.id.touchImageView));
            } else {
                ImageDisplay.getInstance().displayImageLoadEx(this.mReviewModel.getImg_list().get(position).img_real == null ? this.mReviewModel.getImg_list().get(position).img_url : this.mReviewModel.getImg_list().get(position).img_real, (ImageView) view.findViewById(R.id.touchImageView), R.drawable.blog_img);
            }
            view.findViewById(R.id.touchImageView).setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    TouchImageAdapter.this.mListener.onClickImageView();
                }
            });
            container.addView(view);
            return view;
        }

        public void destroyItem(ViewGroup container, int position, Object object) {
            container.removeView((View) object);
        }

        public boolean isViewFromObject(View view, Object object) {
            return view == object;
        }

        public void setOnClickImageListener(OnClickImage listener) {
            this.mListener = listener;
        }
    }

    public void onEventMainThread(ImageListEvent event) {
        this.mModels.clear();
        this.mModels.addAll(event.getModels());
        int currentPosition = ((ViewPager) findViewById(R.id.viewPager)).getCurrentItem();
        this.mAdapter = new TouchImageAdapter((Context) this, (ArrayList) this.mModels);
        this.mAdapter.setOnClickImageListener(this.onClickImageViewListener);
        ((ViewPager) findViewById(R.id.viewPager)).setAdapter(this.mAdapter);
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(currentPosition);
        ((TextView) findViewById(R.id.descriptionLabel)).setText(this.mModels.get(currentPosition).contents);
        setLikeCountLabel(currentPosition);
    }

    public void onEventMainThread(ImageClickEvent event) {
        ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(event.getIndex(), true);
    }

    public void onBackPressed() {
        finish();
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickInstagram(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_image_viewer, (int) R.string.ga_ev_click, (int) R.string.ga_image_viewer_insta);
        if ((this.mModels != null && !this.mModels.isEmpty()) || (this.mReviewModel != null && !this.mReviewModel.getImg_list().isEmpty())) {
            showCircleDialog(true);
            shareToInstagram(((ViewPager) findViewById(R.id.viewPager)).getCurrentItem());
        }
    }

    public void onClickImageList(View view) {
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_image_viewer, (int) R.string.ga_ev_click, (int) R.string.ga_image_viewer_list);
        Intent intent = new Intent(this, ImageListActivity.class);
        if (this.mViewerType == 1) {
            intent.putExtra("model", this.mModel);
        } else {
            intent.putExtra("partnerSno", this.mPartnerSno);
            intent.putExtra("feedSno", this.mFeedSno);
            intent.putExtra("imageModel", this.mReviewModel);
        }
        pushActivity(intent);
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        InstagramModel model;
        if (5858 == requestCode && -1 == resultCode) {
            String fileName = Environment.getExternalStorageDirectory() + ImageDisplay.SHARE_FILE_NAME;
            if (this.mViewerType == 1) {
                model = new InstagramModel(this.mModel.getIntroduce(), this.mModel.getPartner_name1(), String.valueOf(this.mModel.getPartner_sno()), fileName);
            } else {
                model = new InstagramModel("", "", this.mPartnerSno, fileName);
            }
            Intent intent = new Intent(this, InstagramShareActivity.class);
            intent.putExtra("model", model);
            pushActivity(intent);
        }
        showCircleDialog(false);
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
        EventBus.getDefault().unregister(this);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_viewer);
        GAEvent.onGAScreenView(this, R.string.ga_image_viewer);
        if (VERSION.SDK_INT >= 19) {
            findViewById(R.id.statusView).getLayoutParams().height = getStatusBarHeight();
        }
        if (getIntent().hasExtra("model")) {
            this.mModels = new ArrayList<>();
            this.mModel = (StoreDetailModel) getIntent().getSerializableExtra("model");
            if (this.mModel != null) {
                this.mViewerType = 1;
                setViewPager();
                requestAllImageListApi();
            }
        } else if (getIntent().hasExtra("feedSno")) {
            this.mPartnerSno = getIntent().getStringExtra("partnerSno");
            this.mFeedSno = getIntent().getStringExtra("feedSno");
            this.mViewerType = 2;
            if (getIntent().hasExtra("imageModel")) {
                this.mReviewModel = (ReviewInfoResultModel) getIntent().getSerializableExtra("imageModel");
                this.mTotalCount = this.mReviewModel.getImg_list().size();
                ((TextView) findViewById(R.id.titleLabel)).setText((getIntent().getIntExtra("index", 0) + 1) + " / " + this.mTotalCount);
                ((TextView) findViewById(R.id.descriptionLabel)).setText(this.mReviewModel.getImg_list().get(getIntent().getIntExtra("index", 0)).contents);
                findViewById(R.id.likeCountLabel).setVisibility(0);
                ((TextView) findViewById(R.id.likeCountLabel)).setText(this.mReviewModel.getImg_list().get(getIntent().getIntExtra("index", 0)).getLikeCnt());
                setViewPager();
                ((ViewPager) findViewById(R.id.viewPager)).setCurrentItem(getIntent().getIntExtra("index", 0));
                return;
            }
            this.mReviewModel = new ReviewInfoResultModel();
            setViewPager();
            requestReviewInfoApi();
        }
    }

    private void setViewPager() {
        final ViewPager viewPager = (ViewPager) findViewById(R.id.viewPager);
        viewPager.addOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int i, float v, int i1) {
            }

            public void onPageSelected(int position) {
                ((TextView) ViewerActivity.this.findViewById(R.id.titleLabel)).setText((position + 1) + " / " + ViewerActivity.this.mTotalCount);
                if (ViewerActivity.this.mViewerType == 1) {
                    ((TextView) ViewerActivity.this.findViewById(R.id.descriptionLabel)).setText(((StoreAllImageModel) ViewerActivity.this.mModels.get(position)).contents);
                    ViewerActivity.this.setLikeCountLabel(position);
                    if (viewPager.getCurrentItem() == viewPager.getAdapter().getCount() - 1 && ViewerActivity.this.mTotalCount > viewPager.getAdapter().getCount()) {
                        ViewerActivity.this.requestAllImageListApi();
                    }
                } else if (ViewerActivity.this.getIntent().hasExtra("imageModel")) {
                    ((TextView) ViewerActivity.this.findViewById(R.id.descriptionLabel)).setText(ViewerActivity.this.mReviewModel.getImg_list().get(position).contents);
                    ViewerActivity.this.findViewById(R.id.likeCountLabel).setVisibility(0);
                    ((TextView) ViewerActivity.this.findViewById(R.id.likeCountLabel)).setText(ViewerActivity.this.mReviewModel.getImg_list().get(position).getLikeCnt());
                }
            }

            public void onPageScrollStateChanged(int i) {
            }
        });
        viewPager.setPageMargin(20);
        if (this.mViewerType == 1) {
            this.mAdapter = new TouchImageAdapter((Context) this, (ArrayList) this.mModels);
        } else {
            this.mAdapter = new TouchImageAdapter(this, this.mReviewModel, 2);
        }
        this.mAdapter.setOnClickImageListener(this.onClickImageViewListener);
        viewPager.setAdapter(this.mAdapter);
        viewPager.setOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
    }

    public void setLikeCountLabel(int position) {
        if (this.mModels.get(position).user_name == null || this.mModels.get(position).user_name.isEmpty()) {
            findViewById(R.id.likeCountLabel).setVisibility(8);
            return;
        }
        findViewById(R.id.likeCountLabel).setVisibility(0);
        ((TextView) findViewById(R.id.likeCountLabel)).setText(this.mModels.get(position).getLikeCnt());
    }

    private void shareToInstagram(int index) {
        if ((this.mModels != null && !this.mModels.isEmpty()) || (this.mReviewModel != null && !this.mReviewModel.getImg_list().isEmpty())) {
            String url = this.mViewerType == 1 ? this.mModels.get(index).img_real != null ? this.mModels.get(index).img_real : this.mModels.get(index).img_url : this.mReviewModel.getImg_list().get(index).img_real != null ? this.mReviewModel.getImg_list().get(index).img_real : this.mReviewModel.getImg_list().get(index).img_url;
            ImageLoader.getInstance().loadImage(url.replace("save_", ""), new ImageLoadingListener() {
                public void onLoadingStarted(String imageUri, View view) {
                    ViewerActivity.this.showCircleDialog(true);
                }

                public void onLoadingFailed(String imageUri, View view, FailReason failReason) {
                    ViewerActivity.this.showCircleDialog(false);
                }

                public void onLoadingComplete(String imageUri, View view, Bitmap loadedImage) {
                    int size = ImageDisplay.THUMBNAIL_IMAGE_SIZE;
                    ImageDisplay.getInstance();
                    Uri croppedImage = Uri.fromFile(new File(ImageDisplay.saveBitmapToPNG(loadedImage, "")));
                    if (loadedImage.getWidth() < 640 && loadedImage.getHeight() < 640) {
                        size = 306;
                    }
                    CropImageIntentBuilder cropImage = new CropImageIntentBuilder(size, size, croppedImage);
                    cropImage.setOutlineColor(-16537100);
                    cropImage.setScale(false);
                    cropImage.setScaleUpIfNeeded(false);
                    cropImage.setSourceImage(croppedImage);
                    ViewerActivity.this.startActivityForResult(cropImage.getIntent(ViewerActivity.this), CropActivity.CROP_FROM_STORE_DETAIL);
                }

                public void onLoadingCancelled(String imageUri, View view) {
                    ViewerActivity.this.showCircleDialog(false);
                }
            });
        }
    }

    /* access modifiers changed from: private */
    public void requestAllImageListApi() {
        String params = String.format("?partner_sno=%d&page=%d&view_cnt=%d", new Object[]{Integer.valueOf(this.mModel.getPartner_sno()), Integer.valueOf((this.mModels.size() / 10) + 1), Integer.valueOf(10)});
        StoreAllImageListApi request = new StoreAllImageListApi(this);
        request.addGetParam(params);
        request.request(new RequestHandler() {
            public void onStart() {
                ViewerActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                ViewerActivity.this.showCircleDialog(false);
                StoreAllImageResultModel model = (StoreAllImageResultModel) result;
                ViewerActivity.this.mTotalCount = model.getTotal_cnt();
                if (model.getResult_list() != null && model.getResult_list().size() > 0) {
                    int page = (ViewerActivity.this.mModels.size() / 10) + 1;
                    ViewerActivity.this.mModels.addAll(model.getResult_list());
                    int currentPosition = ((ViewPager) ViewerActivity.this.findViewById(R.id.viewPager)).getCurrentItem();
                    ViewerActivity.this.mAdapter = new TouchImageAdapter((Context) ViewerActivity.this, ViewerActivity.this.mModels);
                    ViewerActivity.this.mAdapter.setOnClickImageListener(ViewerActivity.this.onClickImageViewListener);
                    ((ViewPager) ViewerActivity.this.findViewById(R.id.viewPager)).setAdapter(ViewerActivity.this.mAdapter);
                    ((ViewPager) ViewerActivity.this.findViewById(R.id.viewPager)).setCurrentItem(currentPosition);
                    if (1 == page) {
                        int index = ViewerActivity.this.getIntent().getIntExtra("index", 0);
                        if (index > ViewerActivity.this.mModels.size() - 1) {
                            index = 0;
                        }
                        ((ViewPager) ViewerActivity.this.findViewById(R.id.viewPager)).setCurrentItem(index);
                        ((TextView) ViewerActivity.this.findViewById(R.id.descriptionLabel)).setText(((StoreAllImageModel) ViewerActivity.this.mModels.get(index)).contents);
                        ViewerActivity.this.setLikeCountLabel(index);
                    }
                }
            }

            public void onFailure(Exception exception) {
                ViewerActivity.this.showCircleDialog(false);
                ViewerActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ViewerActivity.this.requestAllImageListApi();
                    }
                });
            }

            public void onFinish() {
                ViewerActivity.this.showCircleDialog(false);
                ((TextView) ViewerActivity.this.findViewById(R.id.titleLabel)).setText((((ViewPager) ViewerActivity.this.findViewById(R.id.viewPager)).getCurrentItem() + 1) + " / " + ViewerActivity.this.mTotalCount);
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestReviewInfoApi() {
        String params = String.format("?partner_sno=%s&feed_sno=%s", new Object[]{this.mPartnerSno, this.mFeedSno});
        StoreReviewApi request = new StoreReviewApi(this);
        request.addGetParam(params);
        request.request(new RequestHandler() {
            public void onStart() {
                ViewerActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                ViewerActivity.this.showCircleDialog(false);
                ReviewInfoResultModel model = (ReviewInfoResultModel) result;
                ViewerActivity.this.mTotalCount = model.getImg_list().size();
                if (model == null || model.getImg_list() == null || model.getImg_list().size() == 0) {
                    Toast.makeText(ViewerActivity.this, "\ub9ac\ubdf0\uc774\ubbf8\uc9c0\uac00 \uc5c6\uc2b5\ub2c8\ub2e4.", 0).show();
                    ViewerActivity.this.finish();
                } else if (model != null && model.getResult().equals("Y")) {
                    ViewerActivity.this.mReviewModel = model;
                    ViewerActivity.this.mAdapter = new TouchImageAdapter(ViewerActivity.this, ViewerActivity.this.mReviewModel, 2);
                    ViewerActivity.this.mAdapter.setOnClickImageListener(ViewerActivity.this.onClickImageViewListener);
                    ((ViewPager) ViewerActivity.this.findViewById(R.id.viewPager)).setAdapter(ViewerActivity.this.mAdapter);
                    ((ViewPager) ViewerActivity.this.findViewById(R.id.viewPager)).setCurrentItem(ViewerActivity.this.getIntent().getIntExtra("index", 0));
                    ((TextView) ViewerActivity.this.findViewById(R.id.descriptionLabel)).setText(ViewerActivity.this.mReviewModel.contents);
                    ViewerActivity.this.findViewById(R.id.likeCountLabel).setVisibility(0);
                    ((TextView) ViewerActivity.this.findViewById(R.id.likeCountLabel)).setText(ViewerActivity.this.mReviewModel.getLikeCnt());
                }
            }

            public void onFailure(Exception exception) {
                ViewerActivity.this.showCircleDialog(false);
                ViewerActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ViewerActivity.this.requestReviewInfoApi();
                    }
                });
            }

            public void onFinish() {
                ViewerActivity.this.showCircleDialog(false);
                ((TextView) ViewerActivity.this.findViewById(R.id.titleLabel)).setText((((ViewPager) ViewerActivity.this.findViewById(R.id.viewPager)).getCurrentItem() + 1) + " / " + ViewerActivity.this.mTotalCount);
            }
        });
    }
}