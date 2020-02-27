package com.nuvent.shareat.model.store;

import android.text.TextUtils;
import java.io.Serializable;

public class ReviewImageModel implements Serializable {
    public String cnt_favorite;
    public String cnt_like;
    public String contents;
    public String feed_sno;
    public String img_path;
    public String img_real;
    public String img_save;
    public String img_save_url;
    public int img_sno;
    public String img_thumbnail;
    public String img_thumbnail_url;
    public String img_type;
    public String img_url;
    public String like_cnt;
    public String partner_sno;
    public String user_name;

    public String getLikeCnt() {
        if (!TextUtils.isEmpty(this.cnt_favorite)) {
            return this.cnt_favorite;
        }
        if (!TextUtils.isEmpty(this.cnt_like)) {
            return this.cnt_like;
        }
        if (!TextUtils.isEmpty(this.like_cnt)) {
            return this.like_cnt;
        }
        return "";
    }

    public Boolean isReview() {
        if (TextUtils.isEmpty(this.img_type) || "10".equals(this.img_type)) {
            return Boolean.valueOf(true);
        }
        return Boolean.valueOf(false);
    }

    public String getImg_real() {
        return this.img_real;
    }

    public String getImg_url() {
        return this.img_url;
    }

    public void setImg_url(String img_url2) {
        this.img_url = img_url2;
    }

    public void setImg_real(String img_real2) {
        this.img_real = img_real2;
    }

    public String getThumbnailUrl() {
        String ThumbnailUrl = "";
        if (this.img_thumbnail != null && this.img_thumbnail.length() > 0) {
            ThumbnailUrl = this.img_thumbnail;
        }
        if (this.img_thumbnail_url == null || this.img_thumbnail_url.length() <= 0) {
            return ThumbnailUrl;
        }
        return this.img_thumbnail_url;
    }
}