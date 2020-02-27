package com.nuvent.shareat.model.store;

import android.text.TextUtils;
import com.nuvent.shareat.model.BaseResultModel;
import java.io.Serializable;
import java.util.ArrayList;

public class ReviewInfoResultModel extends BaseResultModel implements Serializable {
    public String cnt_favorite;
    public String cnt_like;
    public String contents;
    public String feed_item;
    public String feed_item_text;
    public int feed_sno;
    public ArrayList<ReviewImageModel> img_list = new ArrayList<>();
    public String like_cnt;

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

    public void setImg_list(ArrayList<ReviewImageModel> img_list2) {
        this.img_list = img_list2;
    }

    public String getCnt_favorite() {
        return this.cnt_favorite;
    }

    public String getCnt_like() {
        return this.cnt_like;
    }

    public String getContents() {
        return this.contents;
    }

    public String getFeed_item() {
        return this.feed_item;
    }

    public String getFeed_item_text() {
        return this.feed_item_text;
    }

    public int getFeed_sno() {
        return this.feed_sno;
    }

    public ArrayList<ReviewImageModel> getImg_list() {
        return this.img_list;
    }
}