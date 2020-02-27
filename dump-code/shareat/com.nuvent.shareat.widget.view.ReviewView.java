package com.nuvent.shareat.widget.view;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.text.method.LinkMovementMethod;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.ImageView.ScaleType;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;
import android.widget.TextView;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.common.ViewerActivity;
import com.nuvent.shareat.activity.main.SearchTagActivity;
import com.nuvent.shareat.activity.menu.InterestActivity;
import com.nuvent.shareat.manager.app.SessionManager;
import com.nuvent.shareat.model.store.ReviewModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.view.CustomClickableSpan.OnSpanClick;
import net.xenix.util.ImageDisplay;

public class ReviewView extends FrameLayout implements OnSpanClick {
    /* access modifiers changed from: private */
    public Context mContext;
    /* access modifiers changed from: private */
    public OnClickView mListener;

    public interface OnClickView {
        void onClickDelete();

        void onClickEdit();

        void onClickLike(View view);
    }

    public ReviewView(Context context) {
        super(context);
        init(context);
    }

    public ReviewView(Context context, AttributeSet attrs) {
        super(context, attrs);
        init(context);
    }

    public ReviewView(Context context, AttributeSet attrs, int defStyleAttr) {
        super(context, attrs, defStyleAttr);
        init(context);
    }

    private void init(Context context) {
        this.mContext = context;
        View.inflate(context, R.layout.cell_review, this);
    }

    public void setData(final ReviewModel model, Typeface typeface) {
        int size;
        ((TextView) findViewById(R.id.timeLabel)).setText(model.getDate());
        ((TextView) findViewById(R.id.contentsLabel)).setText(model.getContents(typeface, new OnSpanClick() {
            public void onClick(String text) {
                Intent intent = new Intent(ReviewView.this.mContext, SearchTagActivity.class);
                if (text.contains(",")) {
                    text = text.replace(",", "");
                }
                intent.putExtra("title", text);
                ((BaseActivity) ReviewView.this.mContext).pushActivity(intent);
            }
        }));
        ((TextView) findViewById(R.id.contentsLabel)).setMovementMethod(LinkMovementMethod.getInstance());
        ((TextView) findViewById(R.id.likeUserLabel)).setText(model.getLikedUserText());
        ((TextView) findViewById(R.id.likeCountLabel)).setText(model.getLikeCount());
        findViewById(R.id.likeButton).setSelected(model.getChk_feed() != null && model.getChk_feed().equals("Y"));
        if (model.isMy()) {
            findViewById(R.id.editLayout).setVisibility(0);
            ImageDisplay.getInstance().displayImageLoadRound(SessionManager.getInstance().getUserModel().getUserImg(), (ImageView) findViewById(R.id.avatarImageView), getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX), (int) R.drawable.list_user_none);
            ((TextView) findViewById(R.id.nameLabel)).setText(SessionManager.getInstance().getUserModel().getUserName());
            findViewById(R.id.deleteButton).setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    ReviewView.this.mListener.onClickDelete();
                }
            });
            findViewById(R.id.editButton).setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    ReviewView.this.mListener.onClickEdit();
                }
            });
        } else {
            findViewById(R.id.editLayout).setVisibility(8);
            if (model.opneYn()) {
                ((TextView) findViewById(R.id.nameLabel)).setText(model.getUser_name());
                ImageDisplay.getInstance().displayImageLoadRound(model.getUser_img(), (ImageView) findViewById(R.id.avatarImageView), getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX), (int) R.drawable.list_user_none);
            } else {
                ((TextView) findViewById(R.id.nameLabel)).setText(getContext().getString(R.string.COMMON_PRIVATE));
                ((ImageView) findViewById(R.id.avatarImageView)).setImageResource(R.drawable.list_user_lock);
            }
        }
        OnClickListener profileClickListener = new OnClickListener() {
            public void onClick(View v) {
                if (!SessionManager.getInstance().hasSession()) {
                    ((BaseActivity) ReviewView.this.mContext).showLoginDialog();
                    return;
                }
                GAEvent.onGaEvent((Activity) (BaseActivity) ReviewView.this.mContext, (int) R.string.ga_store_detail, (int) R.string.store_detile_action_profile_search, (int) R.string.ga_store_detail_review_profile);
                Intent intent = new Intent(ReviewView.this.mContext, InterestActivity.class);
                intent.putExtra("targetUserSno", model.getUser_sno());
                ((BaseActivity) ReviewView.this.mContext).pushActivity(intent);
            }
        };
        findViewById(R.id.nameLabel).setOnClickListener(profileClickListener);
        findViewById(R.id.avatarImageView).setOnClickListener(profileClickListener);
        if (model.img_list.size() > 0) {
            findViewById(R.id.imageLayout).setVisibility(0);
            ((LinearLayout) findViewById(R.id.imageLayout)).removeAllViews();
            int imageSize = getResources().getDimensionPixelOffset(R.dimen.AVATAR_ROUND_SIZE_15OPX);
            int i = 0;
            while (true) {
                if (6 < model.img_list.size()) {
                    size = 6;
                } else {
                    size = model.img_list.size();
                }
                if (i >= size) {
                    break;
                }
                ImageView reviewImage = new ImageView(this.mContext);
                ((ViewGroup) findViewById(R.id.imageLayout)).addView(reviewImage);
                reviewImage.getLayoutParams().height = imageSize;
                reviewImage.getLayoutParams().width = imageSize;
                reviewImage.setScaleType(ScaleType.CENTER_CROP);
                if (i > 0) {
                    ((LayoutParams) reviewImage.getLayoutParams()).leftMargin = getResources().getDimensionPixelOffset(R.dimen.STORE_REVIEW_IMAGE_MARGIN);
                }
                ImageDisplay.getInstance().displayImageLoad(model.img_list.get(i).img_path, reviewImage);
                final int imageIndex = i;
                reviewImage.setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        GAEvent.onGaEvent((Activity) (BaseActivity) ReviewView.this.mContext, (int) R.string.ga_store_detail, (int) R.string.ga_ev_img_search, (int) R.string.ga_store_detail_review_image);
                        Intent intent = new Intent(ReviewView.this.mContext, ViewerActivity.class);
                        intent.putExtra("partnerSno", model.partner_sno);
                        intent.putExtra("feedSno", model.feed_sno);
                        intent.putExtra("index", imageIndex);
                        ((BaseActivity) ReviewView.this.mContext).pushActivity(intent);
                    }
                });
                i++;
            }
        } else {
            findViewById(R.id.imageLayout).setVisibility(8);
        }
        findViewById(R.id.likeLayout).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                if (!SessionManager.getInstance().hasSession()) {
                    ((BaseActivity) ReviewView.this.mContext).showLoginDialog();
                    return;
                }
                ReviewView.this.findViewById(R.id.likeButton).setSelected(!ReviewView.this.findViewById(R.id.likeButton).isSelected());
                ReviewView.this.mListener.onClickLike(ReviewView.this.findViewById(R.id.likeButton));
            }
        });
    }

    public void onClick(String text) {
        Toast.makeText(this.mContext, text, 0).show();
    }

    public void setOnClickViewListener(OnClickView listener) {
        this.mListener = listener;
    }
}