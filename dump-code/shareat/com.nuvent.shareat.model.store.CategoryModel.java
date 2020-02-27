package com.nuvent.shareat.model.store;

import java.util.ArrayList;

public class CategoryModel {
    public String categoryGroupId;
    public String categoryId;
    public String categoryName;
    public String cnt_partner;
    public String img_path;
    public String img_path_2;
    public Boolean isSelected = Boolean.valueOf(false);
    public String levels;
    public ArrayList<CategoryModel> mChildModels;
    public String ord;
    public String upCategoryId;

    public Boolean isSelected() {
        return this.isSelected;
    }

    public void setSelected(boolean isSelected2) {
        this.isSelected = Boolean.valueOf(isSelected2);
    }

    public String getImg_path() {
        return this.img_path;
    }

    public String getImg_path_2() {
        return this.img_path_2;
    }

    public String getCategoryName() {
        return this.categoryName;
    }

    public String getCategoryGroupId() {
        return this.categoryGroupId;
    }

    public String getLevels() {
        return this.levels;
    }

    public String getCategoryId() {
        return this.categoryId;
    }

    public String getOrd() {
        return this.ord;
    }

    public String getCnt_partner() {
        return this.cnt_partner;
    }

    public String getUpCategoryId() {
        return this.upCategoryId;
    }

    public ArrayList<CategoryModel> getChildModels() {
        if (this.mChildModels == null) {
            this.mChildModels = new ArrayList<>();
        }
        return this.mChildModels;
    }

    public void setChildModels(ArrayList<CategoryModel> mChildModels2) {
        this.mChildModels = mChildModels2;
    }
}