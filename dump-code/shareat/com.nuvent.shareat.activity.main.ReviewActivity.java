package com.nuvent.shareat.activity.main;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.text.Html;
import android.text.TextUtils;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.View.OnFocusChangeListener;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.picker.PickerFolderActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.review.ReviewEditApi;
import com.nuvent.shareat.api.review.ReviewImageDeleteApi;
import com.nuvent.shareat.api.review.ReviewUploadApi;
import com.nuvent.shareat.api.review.ReviewWriteApi;
import com.nuvent.shareat.event.ReviewEvent;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.PickerImageModel;
import com.nuvent.shareat.model.ReviewTagModel;
import com.nuvent.shareat.model.ReviewWriteResultModel;
import com.nuvent.shareat.model.store.ReviewModel;
import com.nuvent.shareat.model.store.ReviewModel.StoreReviewImage;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import java.io.File;
import java.util.ArrayList;
import net.xenix.util.ImageDisplay;

public class ReviewActivity extends BaseActivity {
    public static final int REQUEST_CODE_IMAGE_PICKER = 1;
    private boolean isEditMode;
    /* access modifiers changed from: private */
    public ArrayList<StoreReviewImage> mDeleteImageModels = new ArrayList<>();
    /* access modifiers changed from: private */
    public EditText mInputFieldView;
    /* access modifiers changed from: private */
    public ReviewModel mModel;
    private String mPartnerSno;
    /* access modifiers changed from: private */
    public ArrayList<PickerImageModel> mSelectedModels = new ArrayList<>();
    private String mTagIds = "";
    private ArrayList<ReviewTagModel> mTags;

    public void onBackPressed() {
        showConfirmDialog("\ub9ac\ubdf0 \uc791\uc131\uc744 \ucde8\uc18c\ud558\uc2dc\uaca0\uc2b5\ub2c8\uae4c?", new Runnable() {
            public void run() {
                GAEvent.onGaEvent((Activity) ReviewActivity.this, (int) R.string.ga_review_write, (int) R.string.ga_ev_cancle, (int) R.string.ga_pay_review_write_cancle);
                ReviewActivity.this.finish();
            }
        });
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickConfirm(View view) {
        checkValue();
    }

    public void onClickAddImage(View view) {
        int imageModelSize = this.isEditMode ? this.mModel.getImg_list().size() + this.mSelectedModels.size() : this.mSelectedModels.size();
        if (6 == imageModelSize) {
            Toast.makeText(this, "\uc774\ubbf8\uc9c0\ub294 \ucd5c\ub300 6\uc7a5\uae4c\uc9c0 \ub4f1\ub85d \uac00\ub2a5\ud569\ub2c8\ub2e4.", 0).show();
            return;
        }
        Intent intent = new Intent(this, PickerFolderActivity.class);
        intent.putExtra("currentSize", imageModelSize);
        intent.putExtra("selectedModels", this.mSelectedModels);
        animActivityForResult(intent, 1, R.anim.slide_from_right, R.anim.slide_out_to_left);
    }

    /* access modifiers changed from: protected */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (1 == requestCode && -1 == resultCode) {
            this.mSelectedModels = (ArrayList) data.getSerializableExtra("resultData");
            setImageLayout();
        }
    }

    /* access modifiers changed from: private */
    public void setImageLayout() {
        LinearLayout addImageLayout = (LinearLayout) findViewById(R.id.imageAddLayout);
        addImageLayout.removeAllViews();
        if (this.isEditMode && this.mModel != null && this.mModel.getImg_list() != null && this.mModel.getImg_list().size() > 0) {
            for (int i = 0; i < this.mModel.getImg_list().size(); i++) {
                View view = View.inflate(this, R.layout.view_review_image, null);
                view.setTag(Integer.valueOf(i));
                ImageDisplay.getInstance().displayImageLoad(this.mModel.getImg_list().get(i).img_path, (ImageView) view.findViewById(R.id.firstImageView));
                view.findViewById(R.id.removeButton).setTag(Integer.valueOf(i));
                view.findViewById(R.id.removeButton).setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        ReviewActivity.this.mDeleteImageModels.add(ReviewActivity.this.mModel.getImg_list().get(((Integer) v.getTag()).intValue()));
                        ReviewActivity.this.mModel.getImg_list().remove(((Integer) v.getTag()).intValue());
                        ReviewActivity.this.setImageLayout();
                    }
                });
                addImageLayout.addView(view);
            }
        }
        for (int i2 = 0; i2 < this.mSelectedModels.size(); i2++) {
            View view2 = View.inflate(this, R.layout.view_review_image, null);
            view2.setTag(Integer.valueOf(i2));
            ImageDisplay.getInstance().displayImageLoad("file:/" + this.mSelectedModels.get(i2).getImagePath(), (ImageView) view2.findViewById(R.id.firstImageView));
            view2.findViewById(R.id.removeButton).setTag(Integer.valueOf(i2));
            view2.findViewById(R.id.removeButton).setOnClickListener(new OnClickListener() {
                public void onClick(View v) {
                    ReviewActivity.this.mSelectedModels.remove(((Integer) v.getTag()).intValue());
                    ReviewActivity.this.setImageLayout();
                }
            });
            addImageLayout.addView(view2);
        }
        if (6 == addImageLayout.getChildCount()) {
            addImageLayout.setGravity(1);
        } else {
            addImageLayout.setGravity(3);
        }
        addImageLayout.setVisibility(addImageLayout.getChildCount() > 0 ? 0 : 8);
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_review_write);
        GAEvent.onGAScreenView(this, R.string.ga_review_write);
        this.mPartnerSno = getIntent().getStringExtra("partnerSno");
        this.mInputFieldView = (EditText) findViewById(R.id.reviewField);
        if (getIntent().hasExtra("model")) {
            this.isEditMode = true;
            this.mModel = (ReviewModel) getIntent().getSerializableExtra("model");
            this.mInputFieldView.setText(this.mModel.getContents());
            setImageLayout();
            return;
        }
        this.mTags = (ArrayList) getIntent().getSerializableExtra("tags");
        String tagLabelText = "\uc774\uacf3\uc740 ";
        int i = 0;
        while (i < this.mTags.size()) {
            tagLabelText = tagLabelText + this.mTags.get(i).getCode_name() + " ";
            this.mTagIds += (i == this.mTags.size() + -1 ? this.mTags.get(i).getCode_id() : this.mTags.get(i).getCode_id() + "|");
            i++;
        }
        final String tagText = tagLabelText + "\uc88b\uc544\uc694.";
        this.mInputFieldView.setText(Html.fromHtml(getReviewEditMsg(tagText)));
        this.mInputFieldView.setOnFocusChangeListener(new OnFocusChangeListener() {
            public void onFocusChange(View v, boolean hasFocus) {
                if (ReviewActivity.this.mInputFieldView.length() > 0 && ReviewActivity.this.mInputFieldView.getText().toString().contains(ReviewActivity.this.getString(R.string.REVIEW_WRITE_INPUT_HINT))) {
                    String tag = tagText + "\n";
                    ReviewActivity.this.mInputFieldView.setText(tag);
                    ReviewActivity.this.mInputFieldView.setSelection(tag.length());
                }
            }
        });
    }

    private String getReviewEditMsg(String tagText) {
        StringBuffer sb = new StringBuffer();
        if (!TextUtils.isEmpty(tagText)) {
            sb.append("<font color='#1a1c19'>" + tagText + "</font><br/>");
        }
        sb.append(getReviewHintMsg());
        return sb.toString();
    }

    private String getReviewHintMsg() {
        return "<font color='#898b92'>" + getString(R.string.REVIEW_WRITE_INPUT_HINT).replace("\n", "<br/>") + "</font>";
    }

    private void checkValue() {
        String inputText = this.mInputFieldView.getText().toString().trim();
        if (inputText.isEmpty()) {
            Toast.makeText(this, "\ub0b4\uc6a9\uc744 \uc785\ub825\ud574\uc8fc\uc138\uc694.", 0).show();
            showKeyboard(this.mInputFieldView);
            return;
        }
        if (inputText.contains(getString(R.string.REVIEW_WRITE_INPUT_HINT))) {
            inputText = inputText.replace(getString(R.string.REVIEW_WRITE_INPUT_HINT), "");
        }
        if (this.isEditMode) {
            requestReviewEditApi(inputText, this.mModel.getFeed_sno());
            return;
        }
        GAEvent.onGaEvent((Activity) this, (int) R.string.ga_review_write, (int) R.string.ga_ev_reg, (int) R.string.ga_pay_review_write_register);
        requestReviewWriteApi(inputText);
    }

    /* access modifiers changed from: private */
    public void requestReviewDeleteApi(final String imageSno) {
        ReviewImageDeleteApi request = new ReviewImageDeleteApi(this);
        request.addParam("partner_sno", this.mPartnerSno);
        request.addParam("feed_sno", this.mModel.getFeed_sno());
        request.addParam("img_sno", imageSno);
        request.request(new RequestHandler() {
            public void onFailure(Exception exception) {
                ReviewActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ReviewActivity.this.requestReviewDeleteApi(imageSno);
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestReviewUpload(final String feedSno, final String imagePath, final int index) {
        ReviewUploadApi request = new ReviewUploadApi(this);
        request.addParam("partner_sno", this.mPartnerSno);
        request.addParam("feed_sno", feedSno);
        request.addFile("file", imagePath);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                if (((BaseResultModel) result).getResult().equals("E")) {
                    ReviewActivity.this.showCircleDialog(false);
                    ReviewActivity.this.showDialog("\ud30c\uc77c \uc5c5\ub85c\ub4dc\uc5d0 \uc2e4\ud328\ud588\uc2b5\ub2c8\ub2e4.");
                }
            }

            public void onFinish() {
                File file = new File(imagePath);
                if (file.getParentFile().getName().equals(".temp")) {
                    file.delete();
                }
                if (index == ReviewActivity.this.mSelectedModels.size() - 1) {
                    ReviewActivity.this.showCircleDialog(false);
                    EventBus.getDefault().post(new ReviewEvent());
                    ReviewActivity.this.finish();
                }
            }

            public void onFailure(Exception exception) {
                ReviewActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ReviewActivity.this.requestReviewUpload(feedSno, imagePath, index);
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestReviewEditApi(final String inputText, final String feedSno) {
        ReviewEditApi request = new ReviewEditApi(this);
        request.addParam("partner_sno", this.mPartnerSno);
        request.addParam("feed_sno", feedSno);
        request.addParam("contents", inputText);
        request.request(new RequestHandler() {
            public void onStart() {
                ReviewActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                if (!ReviewActivity.this.mDeleteImageModels.isEmpty() || !ReviewActivity.this.mSelectedModels.isEmpty()) {
                    ReviewActivity.this.postImageDelete();
                    return;
                }
                ReviewActivity.this.showCircleDialog(false);
                EventBus.getDefault().post(new ReviewEvent());
                ReviewActivity.this.finish();
            }

            public void onFailure(Exception exception) {
                ReviewActivity.this.showCircleDialog(false);
                ReviewActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ReviewActivity.this.requestReviewEditApi(inputText, feedSno);
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestReviewWriteApi(final String inputText) {
        ReviewWriteApi request = new ReviewWriteApi(this);
        request.addParam("partner_sno", this.mPartnerSno);
        request.addParam("contents", inputText);
        request.addParam("feed_item", this.mTagIds);
        request.request(new RequestHandler() {
            public void onStart() {
                ReviewActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                if (ReviewActivity.this.mSelectedModels.isEmpty()) {
                    ReviewActivity.this.showCircleDialog(false);
                    EventBus.getDefault().post(new ReviewEvent());
                    ReviewActivity.this.finish();
                    return;
                }
                ReviewActivity.this.postUploadImage(((ReviewWriteResultModel) result).getFeed_sno());
            }

            public void onFailure(Exception exception) {
                ReviewActivity.this.showCircleDialog(false);
                ReviewActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        ReviewActivity.this.requestReviewWriteApi(inputText);
                    }
                });
            }
        });
    }

    /* access modifiers changed from: private */
    public void postImageDelete() {
        for (int i = 0; i < this.mDeleteImageModels.size(); i++) {
            requestReviewDeleteApi(this.mDeleteImageModels.get(i).img_sno);
        }
        if (this.mSelectedModels.isEmpty()) {
            showCircleDialog(false);
            EventBus.getDefault().post(new ReviewEvent());
            finish();
        }
        postUploadImage(this.mModel.getFeed_sno());
    }

    /* access modifiers changed from: private */
    public void postUploadImage(String feedSno) {
        String resizePath;
        for (int i = 0; i < this.mSelectedModels.size(); i++) {
            try {
                resizePath = ImageDisplay.getInstance().getResizeBitmap(ImageDisplay.THUMBNAIL_IMAGE_SIZE, this.mSelectedModels.get(i).getImagePath());
            } catch (Exception e) {
                e.printStackTrace();
                resizePath = this.mSelectedModels.get(i).getImagePath();
            }
            requestReviewUpload(feedSno, resizePath, i);
        }
    }
}