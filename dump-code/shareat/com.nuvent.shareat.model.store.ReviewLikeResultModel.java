package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;

public class ReviewLikeResultModel extends BaseResultModel {
    public int like_cnt;
    public String like_user_text;

    public int getLike_cnt() {
        return this.like_cnt;
    }

    public String getLike_user_text() {
        return this.like_user_text == null ? "" : this.like_user_text;
    }
}