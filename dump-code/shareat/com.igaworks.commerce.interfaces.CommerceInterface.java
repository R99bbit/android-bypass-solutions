package com.igaworks.commerce.interfaces;

import android.content.Context;
import com.igaworks.commerce.IgawCommerce.Currency;
import com.igaworks.commerce.IgawCommerce.IgawPaymentMethod;
import com.igaworks.commerce.IgawCommerce.IgawSharingChannel;
import com.igaworks.commerce.IgawCommerceItemModel;
import com.igaworks.commerce.IgawCommerceProductCategoryModel;
import com.igaworks.commerce.IgawCommerceProductModel;
import java.util.List;
import java.util.Map;

public interface CommerceInterface {
    void addToCart(Context context, IgawCommerceProductModel igawCommerceProductModel);

    void addToCart(Context context, IgawCommerceProductModel igawCommerceProductModel, Map<String, String> map);

    void addToCartBulk(Context context, List<IgawCommerceProductModel> list);

    void addToCartBulk(Context context, List<IgawCommerceProductModel> list, Map<String, String> map);

    void addToWishList(Context context, IgawCommerceProductModel igawCommerceProductModel);

    void addToWishList(Context context, IgawCommerceProductModel igawCommerceProductModel, Map<String, String> map);

    void appOpen(Context context);

    void appOpen(Context context, Map<String, String> map);

    void category(Context context, String str);

    void categoryView(Context context, IgawCommerceProductCategoryModel igawCommerceProductCategoryModel);

    void categoryView(Context context, IgawCommerceProductCategoryModel igawCommerceProductCategoryModel, List<IgawCommerceProductModel> list);

    void categoryView(Context context, IgawCommerceProductCategoryModel igawCommerceProductCategoryModel, List<IgawCommerceProductModel> list, Map<String, String> map);

    void categoryView(Context context, IgawCommerceProductCategoryModel igawCommerceProductCategoryModel, Map<String, String> map);

    void deeplinkOpen(Context context, String str);

    void deeplinkOpen(Context context, String str, Map<String, String> map);

    void home(Context context);

    void login(Context context);

    void login(Context context, String str, String str2);

    void login(Context context, Map<String, String> map);

    void logout(Context context);

    void orderConfirmation(Context context, String str, long j, String str2, String str3, String str4);

    void orderReview(Context context, String str, int i, String str2, int i2, String str3, int i3, Currency currency);

    void paymentModeSelection(Context context, String str, int i, String str2, int i2, String str3, int i3, Currency currency);

    void paymentView(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2);

    void paymentView(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2, Map<String, String> map);

    void productDetail(Context context, String str);

    void productView(Context context, IgawCommerceProductModel igawCommerceProductModel);

    void productView(Context context, IgawCommerceProductModel igawCommerceProductModel, Map<String, String> map);

    void purchase(Context context, String str);

    void purchase(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Double d2, IgawPaymentMethod igawPaymentMethod);

    void purchase(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Double d2, IgawPaymentMethod igawPaymentMethod, Map<String, String> map);

    void purchase(Context context, String str, Double d, Currency currency, IgawPaymentMethod igawPaymentMethod);

    void purchase(Context context, String str, Double d, Currency currency, IgawPaymentMethod igawPaymentMethod, Map<String, String> map);

    void purchase(Context context, String str, String str2, String str3, double d, int i, String str4, String str5);

    void purchase(Context context, List<IgawCommerceItemModel> list);

    void purchaseBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2, IgawPaymentMethod igawPaymentMethod);

    void purchaseBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2, IgawPaymentMethod igawPaymentMethod, Map<String, String> map);

    void refund(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d);

    void refund(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Map<String, String> map);

    void refundBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d);

    void refundBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Map<String, String> map);

    void reviewOrder(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Double d2);

    void reviewOrder(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Double d2, Map<String, String> map);

    void reviewOrderBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2);

    void reviewOrderBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2, Map<String, String> map);

    void search(Context context, String str, List<IgawCommerceProductModel> list);

    void search(Context context, String str, List<IgawCommerceProductModel> list, Map<String, String> map);

    void share(Context context, IgawSharingChannel igawSharingChannel, IgawCommerceProductModel igawCommerceProductModel);

    void share(Context context, IgawSharingChannel igawSharingChannel, IgawCommerceProductModel igawCommerceProductModel, Map<String, String> map);

    void shoppingCart(Context context, String str, int i, String str2, int i2, String str3, int i3, Currency currency);

    void subCategory(Context context, String str);

    void subSubCategory(Context context, String str);

    void wishList(Context context, String str, int i, String str2, int i2, String str3, int i3, Currency currency);
}