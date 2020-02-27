package com.igaworks.commerce.model;

import com.igaworks.commerce.IgawPurchaseItem;

public class PurchaseItem extends IgawPurchaseItem {
    private String createdAt;
    private int isDirty;
    private int key;
    private int retryCnt;

    public int getIsDirty() {
        return this.isDirty;
    }

    public void setIsDirty(int isDirty2) {
        this.isDirty = isDirty2;
    }

    public PurchaseItem() {
    }

    public PurchaseItem(int key2, String orderID, String productID, String productName, double price, int quantity, String currency, String category, String createdAt2, int retryCnt2) {
        this.key = key2;
        this.orderID = orderID;
        this.productID = productID;
        this.productName = productName;
        this.price = price;
        this.quantity = quantity;
        this.currency = currency;
        this.category = category;
        this.createdAt = createdAt2;
        this.retryCnt = retryCnt2;
        this.isDirty = 0;
    }

    public PurchaseItem(int key2, String productID, String productName, double price, int quantity, String currency, String category, String createdAt2, int retryCnt2) {
        this.key = key2;
        this.productID = productID;
        this.productName = productName;
        this.price = price;
        this.quantity = quantity;
        this.currency = currency;
        this.category = category;
        this.createdAt = createdAt2;
        this.retryCnt = retryCnt2;
        this.isDirty = 0;
    }

    public String getCreatedAt() {
        return this.createdAt;
    }

    public void setCreatedAt(String createdAt2) {
        this.createdAt = createdAt2;
    }

    public int getKey() {
        return this.key;
    }

    public void setKey(int key2) {
        this.key = key2;
    }

    public int getRetryCnt() {
        return this.retryCnt;
    }

    public void setRetryCnt(int retryCnt2) {
        this.retryCnt = retryCnt2;
    }
}