package com.nuvent.shareat.adapter.store;

import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Build.VERSION;
import android.text.SpannableStringBuilder;
import android.text.style.ForegroundColorSpan;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.widget.view.CustomTypefaceSpan;
import java.util.ArrayList;
import net.xenix.android.widget.LetterSpacingTextView;
import net.xenix.util.ImageDisplay;

public class StoreListAdapter extends BaseAdapter {
    private String head_period_text;
    public Context mContext;
    private LayoutInflater mLayoutInflater;
    /* access modifiers changed from: private */
    public OnClickStoreItem mListener;
    public ArrayList<StoreModel> mModels;
    private Typeface mTypeface;

    public interface OnClickStoreItem {
        void onClickStore(StoreModel storeModel);

        void onClickUser(StoreModel storeModel);
    }

    public class ViewHolder {
        public View m24IconView;
        public View mAvatarImageLayout;
        public ImageView mBallonIcon;
        public TextView mBarcodeStoreLabel;
        public TextView mCategoryLabel;
        public View mCellLayout;
        public TextView mCouponLabel;
        public View mCouponLabelLayout;
        public LetterSpacingTextView mDCLabel;
        public TextView mLocationLabel;
        public TextView mPayCountLabel;
        public ImageView mPayIcon;
        public TextView mPayLabel;
        public TextView mReviewCountLabel;
        public ImageView mStoreImageView;
        public LetterSpacingTextView mStoreNameLabel;
        public LetterSpacingTextView mSubTitleLabel;
        public TextView mTimeFormatLabel;
        public TextView mTimeIconLabel;
        public TextView mTimeLabel;
        public View mTimeLayout;
        public TextView mTopMessageLabel;
        public View mTopMessageLayout;

        public ViewHolder() {
        }
    }

    public String getHeadPeriodText() {
        return this.head_period_text == null ? "" : this.head_period_text;
    }

    public void setHeadPeriodText(String value) {
        this.head_period_text = value;
    }

    public StoreListAdapter(Context context, Typeface typeface, ArrayList<StoreModel> models) {
        this.mContext = context;
        this.mTypeface = typeface;
        this.mModels = models;
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public int getCount() {
        return this.mModels.size();
    }

    public Object getItem(int position) {
        return this.mModels.get(position);
    }

    public long getItemId(int position) {
        return 0;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder h;
        if (convertView == null) {
            convertView = this.mLayoutInflater.inflate(R.layout.cell_store, null);
            h = new ViewHolder();
            h.mCellLayout = convertView.findViewById(R.id.cellLayout);
            h.m24IconView = convertView.findViewById(R.id.icon24ImageView);
            h.mTimeLayout = convertView.findViewById(R.id.timeLayout);
            h.mTopMessageLayout = convertView.findViewById(R.id.topMessageLayout);
            h.mAvatarImageLayout = convertView.findViewById(R.id.avatarImageLayout);
            h.mCouponLabelLayout = convertView.findViewById(R.id.couponLabelLayout);
            h.mPayIcon = (ImageView) convertView.findViewById(R.id.payIconView);
            h.mBallonIcon = (ImageView) convertView.findViewById(R.id.ballonIcon);
            h.mStoreImageView = (ImageView) convertView.findViewById(R.id.storeImageView);
            h.mTimeLabel = (TextView) convertView.findViewById(R.id.timeLabel);
            h.mTimeFormatLabel = (TextView) convertView.findViewById(R.id.timeFormatLabel);
            h.mTopMessageLabel = (TextView) convertView.findViewById(R.id.topMessageLabel);
            h.mCategoryLabel = (TextView) convertView.findViewById(R.id.categoryLabel);
            h.mLocationLabel = (TextView) convertView.findViewById(R.id.locationLabel);
            h.mReviewCountLabel = (TextView) convertView.findViewById(R.id.reviewCount);
            h.mPayLabel = (TextView) convertView.findViewById(R.id.payLabel);
            h.mCouponLabel = (TextView) convertView.findViewById(R.id.couponNameLabel);
            h.mBarcodeStoreLabel = (TextView) convertView.findViewById(R.id.barcodeStoreLabel);
            h.mPayCountLabel = (TextView) convertView.findViewById(R.id.payCountLabel);
            h.mStoreNameLabel = (LetterSpacingTextView) convertView.findViewById(R.id.storeNameLabel);
            h.mSubTitleLabel = (LetterSpacingTextView) convertView.findViewById(R.id.reviewLabel);
            h.mDCLabel = (LetterSpacingTextView) convertView.findViewById(R.id.dcLabel);
            h.mTimeIconLabel = (TextView) convertView.findViewById(R.id.timeIconLabel);
            h.mStoreNameLabel.setCustomLetterSpacing(-1.3f);
            h.mSubTitleLabel.setCustomLetterSpacing(-1.3f);
            h.mDCLabel.setCustomLetterSpacing(-1.3f);
            convertView.setTag(h);
        } else {
            h = (ViewHolder) convertView.getTag();
        }
        final StoreModel model = this.mModels.get(position);
        ImageDisplay.getInstance().displayImageLoad(model.getMainImgUrl(), h.mStoreImageView, (int) R.drawable.main_new_shop_photo);
        h.mStoreNameLabel.setText(model.getPartnerName1());
        h.mTimeLabel.setText(model.getTermEvent()[0]);
        h.mTimeFormatLabel.setText(model.getTermEvent()[1]);
        ((ImageView) convertView.findViewById(R.id.avatarImageView_01)).setImageResource(R.drawable.list_user_none);
        convertView.findViewById(R.id.avatarImageView_01).setVisibility(8);
        ((ImageView) convertView.findViewById(R.id.avatarImageView_02)).setImageResource(R.drawable.list_user_none);
        convertView.findViewById(R.id.avatarImageView_02).setVisibility(8);
        ((ImageView) convertView.findViewById(R.id.avatarImageView_03)).setImageResource(R.drawable.list_user_none);
        convertView.findViewById(R.id.avatarImageView_03).setVisibility(8);
        if (model.getHeadListKind() == null || model.getBoldText() == null || model.getExplainText() == null || this.mTypeface == null) {
            h.m24IconView.setVisibility(8);
            h.mAvatarImageLayout.setVisibility(8);
        } else {
            if (model.getHeadListKind().equals("M")) {
                h.m24IconView.setVisibility(8);
                h.mAvatarImageLayout.setVisibility(8);
            } else {
                h.mTimeIconLabel.setText(getHeadPeriodText());
                h.m24IconView.setVisibility(0);
                h.mAvatarImageLayout.setVisibility(0);
                if (model.getProfileImgList() != null && !model.getProfileImgList().isEmpty()) {
                    int i = 0;
                    while (i < model.getProfileImgList().size()) {
                        int resourceId = R.id.avatarImageView_01;
                        if (3 != model.getProfileImgList().size()) {
                            if (2 != model.getProfileImgList().size()) {
                                switch (i) {
                                    case 0:
                                        resourceId = R.id.avatarImageView_03;
                                        break;
                                    case 1:
                                        resourceId = R.id.avatarImageView_01;
                                        convertView.findViewById(R.id.avatarImageView_01).setVisibility(8);
                                        break;
                                    case 2:
                                        resourceId = R.id.avatarImageView_02;
                                        convertView.findViewById(R.id.avatarImageView_02).setVisibility(8);
                                        break;
                                }
                            } else {
                                switch (i) {
                                    case 0:
                                        resourceId = R.id.avatarImageView_02;
                                        break;
                                    case 1:
                                        resourceId = R.id.avatarImageView_03;
                                        break;
                                    case 2:
                                        resourceId = R.id.avatarImageView_01;
                                        convertView.findViewById(R.id.avatarImageView_01).setVisibility(8);
                                        break;
                                }
                            }
                        } else {
                            switch (i) {
                                case 0:
                                    resourceId = R.id.avatarImageView_01;
                                    break;
                                case 1:
                                    resourceId = R.id.avatarImageView_02;
                                    break;
                                case 2:
                                    resourceId = R.id.avatarImageView_03;
                                    break;
                            }
                        }
                        try {
                            convertView.findViewById(resourceId).setVisibility(0);
                            if (!model.getProfileImgList().get(i).isEmpty()) {
                                if (!model.getProfileImgList().get(i).contains("\ube44\uacf5\uac1c")) {
                                    ImageDisplay.getInstance().displayImageLoadListRound(model.getProfileImgList().get(i), (ImageView) convertView.findViewById(resourceId), this.mContext.getResources().getDimensionPixelOffset(R.dimen.AVATAR_ROUND_SIZE_71PX));
                                } else {
                                    ((ImageView) convertView.findViewById(resourceId)).setImageResource(R.drawable.list_user_lock);
                                }
                                i++;
                            } else {
                                ((ImageView) convertView.findViewById(resourceId)).setImageResource(R.drawable.list_user_none);
                                i++;
                            }
                        } catch (IndexOutOfBoundsException e) {
                            e.printStackTrace();
                            ((ImageView) convertView.findViewById(resourceId)).setImageResource(R.drawable.list_user_none);
                            convertView.findViewById(resourceId).setVisibility(8);
                        }
                    }
                }
            }
            SpannableStringBuilder ssb = new SpannableStringBuilder(model.getBoldText() + model.getExplainText());
            ssb.setSpan(new CustomTypefaceSpan(this.mTypeface), 0, model.getBoldText().length(), 33);
            ssb.setSpan(new ForegroundColorSpan(Color.parseColor("#ff757b8c")), 0, model.getBoldText().length(), 33);
            h.mTopMessageLabel.setText(ssb);
        }
        h.mTimeIconLabel.setVisibility(8);
        h.m24IconView.setVisibility(8);
        h.mDCLabel.setText(model.getCouponInfo());
        h.mCategoryLabel.setText(model.getCategoryName());
        h.mLocationLabel.setText(model.getDongName() + " " + model.getDistanceMark());
        convertView.findViewById(R.id.reviewCount).setVisibility(model.getAppPayYn() ? 0 : 8);
        convertView.findViewById(R.id.ballonIcon).setVisibility(model.getAppPayYn() ? 0 : 8);
        h.mReviewCountLabel.setText(model.getReviewCount());
        if (VERSION.SDK_INT >= 16) {
            h.mBallonIcon.setBackground(this.mContext.getResources().getDrawable(R.drawable.main_ballon_b));
        } else {
            h.mBallonIcon.setBackgroundDrawable(this.mContext.getResources().getDrawable(R.drawable.main_ballon_b));
        }
        h.mSubTitleLabel.setText((model.getEventContents() == null || model.getEventContents().equals("")) ? this.mContext.getResources().getString(R.string.STORE_NEW_REGIST) : model.getEventContents().trim());
        if (model.getCouponGroupSno() == null || model.getCouponGroupSno().equals(AppEventsConstants.EVENT_PARAM_VALUE_NO)) {
            h.mCouponLabelLayout.setVisibility(8);
        } else {
            h.mCouponLabelLayout.setVisibility(0);
            h.mCouponLabel.setText(model.getCouponName());
        }
        if (model.isBarcode()) {
            h.mBarcodeStoreLabel.setVisibility(0);
        } else {
            h.mBarcodeStoreLabel.setVisibility(8);
        }
        if (model.isPayView()) {
            h.mPayLabel.setVisibility(0);
            h.mPayIcon.setVisibility(0);
            h.mPayIcon.setImageResource(R.drawable.icon_store_pay_count);
            h.mPayCountLabel.setText(model.getRecentPayCount());
            h.mPayLabel.setText("\uba85 \uacb0\uc81c");
            h.mPayLabel.setTextColor(Color.parseColor("#ff6385e6"));
            h.mTimeLayout.setVisibility(model.isFirstStore().booleanValue() ? 4 : 0);
        } else {
            h.mPayLabel.setVisibility(4);
            h.mPayIcon.setVisibility(4);
            h.mTimeLayout.setVisibility(8);
            h.mPayCountLabel.setText("");
        }
        if (model.isEventPartner()) {
            h.mDCLabel.setText(model.getAdditionalDesc());
        }
        h.mTopMessageLayout.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreListAdapter.this.mListener.onClickUser(model);
            }
        });
        h.mCellLayout.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                StoreListAdapter.this.mListener.onClickStore(model);
            }
        });
        return convertView;
    }

    public void setOnClickStoreItemListener(OnClickStoreItem listener) {
        this.mListener = listener;
    }
}