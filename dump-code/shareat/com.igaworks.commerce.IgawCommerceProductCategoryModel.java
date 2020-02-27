package com.igaworks.commerce;

public class IgawCommerceProductCategoryModel extends IgawCommerceProductModel {
    String[] categories = new String[5];
    private String categoryFullString = "";

    protected IgawCommerceProductCategoryModel() {
    }

    public IgawCommerceProductCategoryModel(String category1) {
        this.categories[0] = category1;
        setCategoryFullString(this.categories);
    }

    public IgawCommerceProductCategoryModel(String category1, String category2) {
        this.categories[0] = category1;
        this.categories[1] = category2;
        setCategoryFullString(this.categories);
    }

    public IgawCommerceProductCategoryModel(String category1, String category2, String category3) {
        this.categories[0] = category1;
        this.categories[1] = category2;
        this.categories[2] = category3;
        setCategoryFullString(this.categories);
    }

    public IgawCommerceProductCategoryModel(String category1, String category2, String category3, String category4) {
        this.categories[0] = category1;
        this.categories[1] = category2;
        this.categories[2] = category3;
        this.categories[3] = category4;
        setCategoryFullString(this.categories);
    }

    public IgawCommerceProductCategoryModel(String category1, String category2, String category3, String category4, String category5) {
        this.categories[0] = category1;
        this.categories[1] = category2;
        this.categories[2] = category3;
        this.categories[3] = category4;
        this.categories[4] = category5;
        setCategoryFullString(this.categories);
    }

    public static IgawCommerceProductCategoryModel create(String category1) {
        return new IgawCommerceProductCategoryModel(category1);
    }

    public static IgawCommerceProductCategoryModel create(String category1, String category2) {
        return new IgawCommerceProductCategoryModel(category1, category2);
    }

    public static IgawCommerceProductCategoryModel create(String category1, String category2, String category3) {
        return new IgawCommerceProductCategoryModel(category1, category2, category3);
    }

    public static IgawCommerceProductCategoryModel create(String category1, String category2, String category3, String category4) {
        return new IgawCommerceProductCategoryModel(category1, category2, category3, category4);
    }

    public static IgawCommerceProductCategoryModel create(String category1, String category2, String category3, String category4, String category5) {
        return new IgawCommerceProductCategoryModel(category1, category2, category3, category4, category5);
    }

    public String getCategoryFullString() {
        return this.categoryFullString;
    }

    public void setCategoryFullString(String[] categories2) {
        String fullString = "";
        for (int i = 0; i < 5; i++) {
            if (categories2[i] != null && i != 0) {
                fullString = new StringBuilder(String.valueOf(fullString)).append(".").append(categories2[i]).toString();
            } else if (categories2[i] != null && i == 0) {
                fullString = new StringBuilder(String.valueOf(fullString)).append(categories2[i]).toString();
            }
        }
        this.categoryFullString = fullString;
    }
}