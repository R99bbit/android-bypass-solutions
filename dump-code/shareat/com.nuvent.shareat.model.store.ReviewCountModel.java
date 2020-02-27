package com.nuvent.shareat.model.store;

import com.nuvent.shareat.model.BaseResultModel;

public class ReviewCountModel extends BaseResultModel {
    private int insta_count;
    private int naver_count;
    private int shareat_count;

    public int getInsta_count() {
        return this.insta_count;
    }

    public void setInsta_count(int insta_count2) {
        this.insta_count = insta_count2;
    }

    public int getShareat_count() {
        return this.shareat_count;
    }

    public void setShareat_count(int shareat_count2) {
        this.shareat_count = shareat_count2;
    }

    public int getNaver_count() {
        return this.naver_count;
    }

    public void setNaver_count(int naver_count2) {
        this.naver_count = naver_count2;
    }
}