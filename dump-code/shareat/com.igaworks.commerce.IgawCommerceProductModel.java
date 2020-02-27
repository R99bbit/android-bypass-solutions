package com.igaworks.commerce;

import android.content.Context;
import android.util.Log;
import com.igaworks.commerce.IgawCommerce.Currency;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.impl.CommonFrameworkImpl;
import java.util.HashMap;
import java.util.Map;

public class IgawCommerceProductModel {
    private static Context context;
    protected String category;
    protected Currency currency;
    protected Double discount;
    protected Map<String, String> extraAttrsMap;
    protected Double price;
    protected String productID;
    protected String productName;
    protected Integer quantity;

    public IgawCommerceProductModel() {
        this.productID = "";
        this.productName = "";
        this.price = Double.valueOf(0.0d);
        this.discount = Double.valueOf(0.0d);
        this.quantity = Integer.valueOf(1);
    }

    public IgawCommerceProductModel(String productID2, String productName2, Double price2, Double discount2, Integer quantity2, Currency currency2, IgawCommerceProductCategoryModel category2, IgawCommerceProductAttrModel attr) {
        this.productID = "";
        this.productName = "";
        this.price = Double.valueOf(0.0d);
        this.discount = Double.valueOf(0.0d);
        this.quantity = Integer.valueOf(1);
        this.extraAttrsMap = null;
        this.extraAttrsMap = new HashMap();
        if (attr != null) {
            for (int i = 0; i < 5; i++) {
                if (attr.key[i] != null && !attr.key[i].equals("")) {
                    this.extraAttrsMap.put(attr.key[i], attr.value[i]);
                }
            }
        }
        this.productID = productID2;
        this.productName = productName2;
        this.price = price2;
        this.discount = discount2;
        this.quantity = quantity2;
        this.currency = currency2;
        if (category2 != null) {
            this.category = category2.getCategoryFullString();
        }
    }

    public static IgawCommerceProductModel create(String productID2, String productName2, Double price2, Double discount2, Integer quantity2, Currency currency2, IgawCommerceProductCategoryModel category2, IgawCommerceProductAttrModel attr) {
        return new IgawCommerceProductModel(productID2, productName2, price2, discount2, quantity2, currency2, category2, attr);
    }

    public String getProductName() {
        return this.productName;
    }

    public IgawCommerceProductModel setProductName(String productName2) {
        this.productName = productName2;
        return this;
    }

    public int getQuantity() {
        return this.quantity.intValue();
    }

    public IgawCommerceProductModel setQuantity(int quantity2) {
        this.quantity = Integer.valueOf(quantity2);
        return this;
    }

    public String getProductID() {
        return this.productID;
    }

    public IgawCommerceProductModel setProductID(String productID2) {
        this.productID = productID2;
        return this;
    }

    public double getPrice() {
        return this.price.doubleValue();
    }

    public IgawCommerceProductModel setPrice(double price2) {
        this.price = Double.valueOf(price2);
        return this;
    }

    public double getDiscount() {
        return this.discount.doubleValue();
    }

    public IgawCommerceProductModel setDiscount(double discount2) {
        this.discount = Double.valueOf(discount2);
        return this;
    }

    public Currency getCurrency() {
        return this.currency;
    }

    public IgawCommerceProductModel setCurrency(Currency currency2) {
        this.currency = currency2;
        return this;
    }

    public String getCategory() {
        return this.category;
    }

    public IgawCommerceProductModel setCategory(IgawCommerceProductCategoryModel category2) {
        this.category = category2.getCategoryFullString();
        return this;
    }

    public IgawCommerceProductModel setExtraAttrs(IgawCommerceProductAttrModel attr) {
        this.extraAttrsMap = null;
        this.extraAttrsMap = new HashMap();
        if (attr != null) {
            for (int i = 0; i < 5; i++) {
                if (attr.key[i] != null && !attr.key[i].equals("")) {
                    this.extraAttrsMap.put(attr.key[i], attr.value[i]);
                }
            }
        }
        return this;
    }

    public IgawCommerceProductModel setExtraAttrs(String key, String val) {
        if (this.extraAttrsMap == null) {
            this.extraAttrsMap = new HashMap();
        }
        if (context == null) {
            context = CommonFrameworkImpl.getContext();
        }
        if (context == null) {
            Log.e(IgawConstant.QA_TAG, "eventFired >> Context is null. check start session is called.");
        }
        if (this.extraAttrsMap.size() >= 5) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceProductAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
        } else {
            if (key == null) {
                key = "";
            }
            if (val == null) {
                val = "";
            }
            this.extraAttrsMap.put(key, val);
        }
        return this;
    }

    public Map<String, String> getExtraAttrs() {
        return this.extraAttrsMap;
    }
}