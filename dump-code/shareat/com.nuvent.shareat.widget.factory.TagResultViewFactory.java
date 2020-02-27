package com.nuvent.shareat.widget.factory;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.text.Spannable;
import android.text.SpannableString;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ImageView;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.StoreDetailActivity;
import com.nuvent.shareat.activity.menu.InterestActivity;
import com.nuvent.shareat.model.search.TagModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.view.CustomTypefaceSpan;
import java.util.ArrayList;
import net.xenix.util.ImageDisplay;

public class TagResultViewFactory {
    public static View createView(Context context, TagModel model, Typeface typeface, String title) {
        if (model.getType().equals("P")) {
            View convertView = View.inflate(context, R.layout.cell_gnb_search_store, null);
            ((TextView) convertView.findViewById(R.id.storeTitleLabel)).setText(model.getPartnerName1());
            ((TextView) convertView.findViewById(R.id.tagsLabel)).setText(model.getHashTag());
            ImageView coverImageView = (ImageView) convertView.findViewById(R.id.coverImageView);
            if (model.getMainImgUrl() != null && !model.getMainImgUrl().isEmpty()) {
                ImageDisplay.getInstance().displayImageLoad(model.getMainImgUrl(), coverImageView);
            }
            View findViewById = convertView.findViewById(R.id.rootLayout);
            final TagModel tagModel = model;
            final Context context2 = context;
            AnonymousClass1 r0 = new OnClickListener() {
                public void onClick(View v) {
                    if (tagModel.getPartnerSno() != null && !tagModel.getPartnerSno().isEmpty()) {
                        StoreModel storeModel = tagModel;
                        Intent intent = new Intent(context2, StoreDetailActivity.class);
                        intent.putExtra("model", storeModel);
                        ((BaseActivity) context2).pushActivity(intent);
                    }
                }
            };
            findViewById.setOnClickListener(r0);
            return convertView;
        } else if (!model.getType().equals("F")) {
            return View.inflate(context, R.layout.cell_gnb_search_review, null);
        } else {
            View convertView2 = View.inflate(context, R.layout.cell_gnb_search_review, null);
            TextView contentLabel = (TextView) convertView2.findViewById(R.id.contentLabel);
            if (!(model.getPartnerName1() == null || model.getDongName() == null)) {
                ((TextView) convertView2.findViewById(R.id.storeName)).setText(model.getPartnerName1() + "(" + model.getDongName() + ")");
            }
            contentLabel.setText(model.getContents());
            ArrayList<String> tagStringList = new ArrayList<>();
            for (String splitTag = model.getContents(); splitTag.contains("#"); splitTag = splitTag.replaceFirst("#", "")) {
                String temp = splitTag.substring(splitTag.indexOf("#"), splitTag.length());
                try {
                    tagStringList.add(temp.substring(0, temp.indexOf(" ")));
                } catch (StringIndexOutOfBoundsException e) {
                    e.printStackTrace();
                    tagStringList.add(temp.substring(0, temp.length()));
                }
            }
            String spanText = model.getContents();
            Spannable span = new SpannableString(spanText);
            for (int i = 0; i < tagStringList.size(); i++) {
                String substring = spanText.substring(spanText.indexOf((String) tagStringList.get(i)), spanText.indexOf((String) tagStringList.get(i)) + ((String) tagStringList.get(i)).length());
                CustomTypefaceSpan customTypefaceSpan = new CustomTypefaceSpan(typeface);
                span.setSpan(customTypefaceSpan, spanText.indexOf((String) tagStringList.get(i)), ((String) tagStringList.get(i)).length() + spanText.indexOf((String) tagStringList.get(i)), 0);
            }
            contentLabel.setText(span);
            ((TextView) convertView2.findViewById(R.id.dateLabel)).setText(model.getEventRegDate());
            ((TextView) convertView2.findViewById(R.id.userNameLabel)).setText(model.getUserName());
            ImageView avatarImageView = (ImageView) convertView2.findViewById(R.id.avatarImageView);
            ImageDisplay.getInstance().displayImageLoadListRound(model.getUserImg(), avatarImageView, context.getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX));
            final Context context3 = context;
            final TagModel tagModel2 = model;
            AnonymousClass2 r02 = new OnClickListener() {
                public void onClick(View v) {
                    GAEvent.onGaEvent((Activity) (BaseActivity) context3, (int) R.string.ga_store_detail, (int) R.string.store_detile_action_profile_search, (int) R.string.ga_store_detail_review_profile);
                    Intent intent = new Intent(context3, InterestActivity.class);
                    intent.putExtra("targetUserSno", tagModel2.getUserSno());
                    ((BaseActivity) context3).pushActivity(intent);
                }
            };
            avatarImageView.setOnClickListener(r02);
            ((TextView) convertView2.findViewById(R.id.userNameLabel)).setOnClickListener(r02);
            if (model.getReviewImgList() != null && !model.getReviewImgList().isEmpty()) {
                convertView2.findViewById(R.id.reviewImageLayout).setVisibility(0);
                int i2 = 0;
                while (true) {
                    if (i2 < (model.getReviewImgList().size() > 6 ? 6 : model.getReviewImgList().size())) {
                        int resourceId = R.id.reviewImage01;
                        switch (i2) {
                            case 0:
                                resourceId = R.id.reviewImage01;
                                break;
                            case 1:
                                resourceId = R.id.reviewImage02;
                                break;
                            case 2:
                                resourceId = R.id.reviewImage03;
                                break;
                            case 3:
                                resourceId = R.id.reviewImage04;
                                break;
                            case 4:
                                resourceId = R.id.reviewImage05;
                                break;
                            case 5:
                                resourceId = R.id.reviewImage06;
                                break;
                        }
                        ImageDisplay.getInstance().displayImageLoad(model.getReviewImgList().get(i2).imgPath, (ImageView) convertView2.findViewById(resourceId));
                        View findViewById2 = convertView2.findViewById(resourceId);
                        final TagModel tagModel3 = model;
                        final Context context4 = context;
                        AnonymousClass3 r03 = new OnClickListener() {
                            public void onClick(View v) {
                                if (tagModel3.getPartnerSno() != null && !tagModel3.getPartnerSno().isEmpty()) {
                                    StoreModel storeModel = new StoreModel();
                                    storeModel.setFavorite(tagModel3.getFavoriteYn());
                                    storeModel.setPartnerName1(tagModel3.getPartnerName1());
                                    storeModel.setPartnerSno(tagModel3.getPartnerSno());
                                    Intent intent = new Intent(context4, StoreDetailActivity.class);
                                    intent.putExtra("model", storeModel);
                                    intent.putExtra("isReviewTop", "");
                                    ((BaseActivity) context4).pushActivity(intent);
                                }
                            }
                        };
                        findViewById2.setOnClickListener(r03);
                        i2++;
                    }
                }
            }
            final TagModel tagModel4 = model;
            final Context context5 = context;
            AnonymousClass4 r04 = new OnClickListener() {
                public void onClick(View v) {
                    if (tagModel4.getPartnerSno() != null && !tagModel4.getPartnerSno().isEmpty()) {
                        StoreModel storeModel = new StoreModel();
                        storeModel.setFavorite(tagModel4.getFavoriteYn());
                        storeModel.setPartnerName1(tagModel4.getPartnerName1());
                        storeModel.setPartnerSno(tagModel4.getPartnerSno());
                        Intent intent = new Intent(context5, StoreDetailActivity.class);
                        intent.putExtra("model", storeModel);
                        intent.putExtra("isReviewTop", "");
                        ((BaseActivity) context5).pushActivity(intent);
                    }
                }
            };
            convertView2.setOnClickListener(r04);
            return convertView2;
        }
    }
}