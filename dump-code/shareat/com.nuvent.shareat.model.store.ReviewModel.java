package com.nuvent.shareat.model.store;

import android.graphics.Typeface;
import android.text.Spannable;
import android.text.SpannableStringBuilder;
import android.text.TextUtils;
import com.facebook.appevents.AppEventsConstants;
import com.igaworks.interfaces.CommonInterface;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.SpanTagModel;
import com.nuvent.shareat.util.ShareAtUtil;
import com.nuvent.shareat.widget.view.CustomClickableSpan;
import com.nuvent.shareat.widget.view.CustomClickableSpan.OnSpanClick;
import com.nuvent.shareat.widget.view.CustomTypefaceSpan;
import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;

public class ReviewModel extends StoreListModel implements Serializable {
    public String chk_feed;
    public String chk_user;
    public int cnt_like;
    public String contents;
    public String feed_sno;
    public ArrayList<StoreReviewImage> img_list = new ArrayList<>();
    public String like_user_text;
    public String open_yn;
    public String partner_name;
    public String partner_sno;
    public String pay_type;
    public String pay_type_text;
    public String reg_date;
    public String user_img;
    public String user_name;
    public String user_sno;

    public class StoreReviewImage implements Serializable {
        public String img_path;
        public String img_sno;

        public StoreReviewImage() {
        }
    }

    public String getPartnerName() {
        return this.partner_name;
    }

    public void setPartnerName(String partner_name2) {
        this.partner_name = partner_name2;
    }

    public String getUser_img() {
        return this.user_img;
    }

    public String getUser_name() {
        return this.user_name;
    }

    public String getDate() {
        if (this.reg_date == null) {
            return "";
        }
        SimpleDateFormat format = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.getDefault());
        try {
            Date date = format.parse(this.reg_date);
            format.applyPattern("yyyy.MM.dd HH:mm:ss");
            return format.format(date);
        } catch (ParseException e) {
            e.printStackTrace();
            return this.reg_date;
        }
    }

    public Spannable getContents(Typeface typeface, OnSpanClick onSpanClick) {
        if (TextUtils.isEmpty(this.contents)) {
            return null;
        }
        SpannableStringBuilder ssb = new SpannableStringBuilder(this.contents);
        Iterator<SpanTagModel> it = ShareAtUtil.getTags(this.contents).iterator();
        while (it.hasNext()) {
            SpanTagModel tag = it.next();
            ssb.setSpan(new CustomTypefaceSpan(typeface), tag.start, tag.end, 33);
            ssb.setSpan(new CustomClickableSpan(this.contents.substring(tag.start, tag.end), onSpanClick), tag.start, tag.end, 33);
        }
        return ssb;
    }

    public boolean hasImage() {
        return this.img_list.size() > 0;
    }

    public boolean isMy() {
        return this.chk_user != null && this.chk_user.equals("Y");
    }

    public String getLikeCount() {
        return String.valueOf(this.cnt_like);
    }

    public boolean hasLike() {
        return this.cnt_like > 0;
    }

    public boolean hasMyLike() {
        return this.chk_feed != null && this.chk_feed.equals("Y");
    }

    public void reverseLike() {
        this.chk_feed = (this.chk_feed == null || !this.chk_feed.equals("Y")) ? "Y" : "N";
    }

    public String getLikedUserText() {
        if (TextUtils.isEmpty(this.like_user_text)) {
            return "";
        }
        return this.like_user_text + "\uc774 \uc88b\uc544\ud569\ub2c8\ub2e4.";
    }

    public boolean opneYn() {
        return this.open_yn != null && "0Y".contains(this.open_yn);
    }

    public String getChk_feed() {
        return this.chk_feed;
    }

    public ArrayList<StoreReviewImage> getImg_list() {
        return this.img_list;
    }

    public String getUser_sno() {
        return this.user_sno;
    }

    public String getChk_user() {
        return this.chk_user;
    }

    public String getPay_type() {
        return this.pay_type;
    }

    public String getContents() {
        return this.contents;
    }

    public String getLike_user_text() {
        return this.like_user_text;
    }

    public String getPay_type_text() {
        return this.pay_type_text;
    }

    public String getFeed_sno() {
        return this.feed_sno;
    }

    public String getReg_date() {
        return this.reg_date;
    }

    public int getCnt_like() {
        return this.cnt_like;
    }

    public String getOpen_yn() {
        return this.open_yn;
    }

    public boolean isPaied() {
        if (this.pay_type == null) {
            this.pay_type = AppEventsConstants.EVENT_PARAM_VALUE_NO;
        }
        return this.pay_type != null;
    }

    public int getResIdByPayType() {
        if (isPaied()) {
            return this.pay_type.equals(AppEventsConstants.EVENT_PARAM_VALUE_NO) ? R.drawable.review_only : R.drawable.review_nbbang;
        }
        return 0;
    }

    public boolean hasImg() {
        return this.img_list.size() > 0;
    }
}