package com.nuvent.shareat.dialog;

import android.content.Context;
import android.view.View;
import android.view.View.OnClickListener;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.ReviewTagModel;
import java.util.ArrayList;

public class ReviewTypeDialog extends BaseDialog implements OnClickListener {
    public static final String REVIEW_TYPE_01 = "#\ub9db";
    public static final String REVIEW_TYPE_02 = "#\uac00\uaca9";
    public static final String REVIEW_TYPE_03 = "#\uc11c\ube44\uc2a4";
    public static final String REVIEW_TYPE_04 = "#\uc704\uc0dd\uc0c1\ud0dc";
    public static final String REVIEW_TYPE_05 = "#\ubd84\uc704\uae30";
    private View mContentView;
    private DialogClickListener mListener;

    public interface DialogClickListener {
        void onClickNext(ArrayList<ReviewTagModel> arrayList);
    }

    public ReviewTypeDialog(Context context) {
        super(context);
        init();
    }

    private void init() {
        this.mContentView = View.inflate(getContext(), R.layout.dialog_review_type, null);
        this.mContentView.findViewById(R.id.reviewType01).setOnClickListener(this);
        this.mContentView.findViewById(R.id.reviewType02).setOnClickListener(this);
        this.mContentView.findViewById(R.id.reviewType03).setOnClickListener(this);
        this.mContentView.findViewById(R.id.reviewType04).setOnClickListener(this);
        this.mContentView.findViewById(R.id.reviewType05).setOnClickListener(this);
        this.mContentView.findViewById(R.id.nextButton).setOnClickListener(this);
        setContentView(this.mContentView);
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.nextButton /*2131296943*/:
                ArrayList<ReviewTagModel> tags = new ArrayList<>();
                if (this.mContentView.findViewById(R.id.reviewType01).isSelected()) {
                    ReviewTagModel model = new ReviewTagModel();
                    model.setCode_id("10");
                    model.setCode_name(REVIEW_TYPE_01);
                    tags.add(model);
                }
                if (this.mContentView.findViewById(R.id.reviewType02).isSelected()) {
                    ReviewTagModel model2 = new ReviewTagModel();
                    model2.setCode_id("20");
                    model2.setCode_name(REVIEW_TYPE_02);
                    tags.add(model2);
                }
                if (this.mContentView.findViewById(R.id.reviewType03).isSelected()) {
                    ReviewTagModel model3 = new ReviewTagModel();
                    model3.setCode_id("30");
                    model3.setCode_name(REVIEW_TYPE_03);
                    tags.add(model3);
                }
                if (this.mContentView.findViewById(R.id.reviewType04).isSelected()) {
                    ReviewTagModel model4 = new ReviewTagModel();
                    model4.setCode_id("40");
                    model4.setCode_name(REVIEW_TYPE_04);
                    tags.add(model4);
                }
                if (this.mContentView.findViewById(R.id.reviewType05).isSelected()) {
                    ReviewTagModel model5 = new ReviewTagModel();
                    model5.setCode_id("50");
                    model5.setCode_name(REVIEW_TYPE_05);
                    tags.add(model5);
                }
                this.mListener.onClickNext(tags);
                dismiss();
                return;
            case R.id.reviewType01 /*2131297212*/:
            case R.id.reviewType02 /*2131297213*/:
            case R.id.reviewType03 /*2131297214*/:
            case R.id.reviewType04 /*2131297215*/:
            case R.id.reviewType05 /*2131297216*/:
                v.setSelected(!v.isSelected());
                return;
            default:
                return;
        }
    }

    public void setOnDialogClickListener(DialogClickListener listener) {
        this.mListener = listener;
    }
}