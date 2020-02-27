package com.nuvent.shareat.model.search;

import com.nuvent.shareat.model.store.StoreModel;
import java.util.ArrayList;

public class TagModel extends StoreModel {
    private String contents;
    private String feedSno;
    private String hashTag;
    private String imgPaopenYNth;
    private String likeUserText;
    private String partnerIntroduce;
    private String payType;
    private String payTypeText;
    private int reviewImgCount;
    private ArrayList<ReviewImage> reviewImgList = new ArrayList<>();
    private String type;
    private String userImg;
    private String userName;
    private String userSno;

    public class ReviewImage {
        public String imgPath;
        public String imgSno;

        public ReviewImage() {
        }
    }

    public String getType() {
        return this.type;
    }

    public void setType(String type2) {
        this.type = type2;
    }

    public String getFeedSno() {
        return this.feedSno;
    }

    public void setFeedSno(String feedSno2) {
        this.feedSno = feedSno2;
    }

    public String getContents() {
        return this.contents;
    }

    public void setContents(String contents2) {
        this.contents = contents2;
    }

    public String getLikeUserText() {
        return this.likeUserText;
    }

    public void setLikeUserText(String likeUserText2) {
        this.likeUserText = likeUserText2;
    }

    public String getPayType() {
        return this.payType;
    }

    public void setPayType(String payType2) {
        this.payType = payType2;
    }

    public String getPayTypeText() {
        return this.payTypeText;
    }

    public void setPayTypeText(String payTypeText2) {
        this.payTypeText = payTypeText2;
    }

    public int getReviewImgCount() {
        return this.reviewImgCount;
    }

    public void setReviewImgCount(int reviewImgCount2) {
        this.reviewImgCount = reviewImgCount2;
    }

    public ArrayList<ReviewImage> getReviewImgList() {
        return this.reviewImgList;
    }

    public void setReviewImgList(ArrayList<ReviewImage> reviewImgList2) {
        this.reviewImgList = reviewImgList2;
    }

    public String getImgPaopenYNth() {
        return this.imgPaopenYNth;
    }

    public void setImgPaopenYNth(String imgPaopenYNth2) {
        this.imgPaopenYNth = imgPaopenYNth2;
    }

    public String getPartnerIntroduce() {
        return this.partnerIntroduce;
    }

    public void setPartnerIntroduce(String partnerIntroduce2) {
        this.partnerIntroduce = partnerIntroduce2;
    }

    public String getHashTag() {
        return this.hashTag;
    }

    public void setHashTag(String hashTag2) {
        this.hashTag = hashTag2;
    }

    public String getUserName() {
        return this.userName;
    }

    public void setUserName(String userName2) {
        this.userName = userName2;
    }

    public String getUserImg() {
        return this.userImg;
    }

    public void setUserImg(String userImg2) {
        this.userImg = userImg2;
    }

    public String getUserSno() {
        return this.userSno;
    }

    public void setUserSno(String userSno2) {
        this.userSno = userSno2;
    }
}