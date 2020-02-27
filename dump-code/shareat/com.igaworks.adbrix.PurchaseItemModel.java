package com.igaworks.adbrix;

import com.igaworks.adbrix.IgawAdbrix.Currency;

public class PurchaseItemModel {
    protected String category = "unknown";
    protected Currency currency;
    protected String orderId = "unknown";
    protected double price = 0.0d;
    protected String productId = "unknown";
    protected String productName = "unknown";
    protected int quantity = 1;

    protected PurchaseItemModel() {
    }

    public PurchaseItemModel(String orderID, String productID, String productName2, double price2, int quantity2, Currency currency2, String category2) {
        if (orderID != null && orderID.length() > 0) {
            this.orderId = orderID;
        }
        if (productID != null && productID.length() > 0) {
            this.productId = productID;
        }
        if (productName2 != null && productName2.length() > 0) {
            this.productName = productName2;
        }
        this.price = price2;
        this.quantity = quantity2;
        this.currency = currency2;
        if (category2 != null && category2.length() > 0) {
            this.category = category2;
        }
    }

    @Deprecated
    public PurchaseItemModel(String productID, String productName2, double price2, int quantity2, Currency currency2, String category2) {
        if (productID != null && productID.length() > 0) {
            this.productId = productID;
        }
        if (productName2 != null && productName2.length() > 0) {
            this.productName = productName2;
        }
        this.quantity = quantity2;
        this.currency = currency2;
        if (category2 != null && category2.length() > 0) {
            this.category = category2;
        }
    }

    public static PurchaseItemModel create(String orderID, String productID, String productName2, double price2, int quantity2, Currency currency2, String category2) {
        return new PurchaseItemModel(orderID, productID, productName2, price2, quantity2, currency2, category2);
    }

    public String getOrderID() {
        return this.orderId;
    }

    public void setOrderID(String orderID) {
        this.orderId = orderID;
    }

    public String getProductName() {
        return this.productName;
    }

    public void setProductName(String productName2) {
        this.productName = productName2;
    }

    public int getQuantity() {
        return this.quantity;
    }

    public void setQuantity(int quantity2) {
        this.quantity = quantity2;
    }

    public String getProductID() {
        return this.productId;
    }

    public void setProductID(String productID) {
        this.productId = productID;
    }

    public double getPrice() {
        return this.price;
    }

    public void setPrice(double price2) {
        this.price = price2;
    }

    public Currency getCurrency() {
        return this.currency;
    }

    public void setCurrency(Currency currency2) {
        this.currency = currency2;
    }

    public String getCategory() {
        return this.category;
    }

    public void setCategory(String category2) {
        this.category = category2;
    }
}