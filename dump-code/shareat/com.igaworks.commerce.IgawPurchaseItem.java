package com.igaworks.commerce;

public class IgawPurchaseItem {
    protected String category = "";
    protected String currency = "";
    protected String orderID = "";
    protected double price = 0.0d;
    protected String productID = "";
    protected String productName = "";
    protected int quantity = 1;

    protected IgawPurchaseItem() {
    }

    public IgawPurchaseItem(String orderID2, String productID2, String productName2, double price2, int quantity2, String currency2, String category2) {
        this.orderID = orderID2;
        this.productID = productID2;
        this.productName = productName2;
        this.price = price2;
        this.quantity = quantity2;
        this.currency = currency2;
        this.category = category2;
    }

    public IgawPurchaseItem(String productID2, String productName2, double price2, int quantity2, String currency2, String category2) {
        this.productID = productID2;
        this.productName = productName2;
        this.price = price2;
        this.quantity = quantity2;
        this.currency = currency2;
        this.category = category2;
    }

    public static IgawPurchaseItem create(String orderID2, String productID2, String productName2, double price2, int quantity2, String currency2, String category2) {
        return new IgawPurchaseItem(orderID2, productID2, productName2, price2, quantity2, currency2, category2);
    }

    public String getOrderID() {
        return this.orderID;
    }

    public void setOrderID(String orderID2) {
        this.orderID = orderID2;
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
        return this.productID;
    }

    public void setProductID(String productID2) {
        this.productID = productID2;
    }

    public double getPrice() {
        return this.price;
    }

    public void setPrice(double price2) {
        this.price = price2;
    }

    public String getCurrency() {
        return this.currency;
    }

    public void setCurrency(String currency2) {
        this.currency = currency2;
    }

    public String getCategory() {
        return this.category;
    }

    public void setCategory(String category2) {
        this.category = category2;
    }
}