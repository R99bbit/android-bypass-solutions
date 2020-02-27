package com.igaworks.adbrix.interfaces;

import android.app.Activity;
import android.content.Context;
import com.igaworks.commerce.IgawCommerce.Currency;
import com.igaworks.commerce.IgawCommerce.IgawPaymentMethod;
import com.igaworks.commerce.IgawCommerce.IgawSharingChannel;
import com.igaworks.commerce.IgawCommerceItemModel;
import com.igaworks.commerce.IgawCommerceProductCategoryModel;
import com.igaworks.commerce.IgawCommerceProductModel;
import com.igaworks.core.RequestParameter;
import com.igaworks.interfaces.CommonInterface;
import java.util.List;
import java.util.Map;

public interface ADBrixInterface extends CommonInterface {
    public static final String COUPON_GROUP = "3rd_party_coupon";

    public enum CohortVariable {
        COHORT_1(1, RequestParameter.COHORT_1_NAME),
        COHORT_2(2, RequestParameter.COHORT_2_NAME),
        COHORT_3(3, RequestParameter.COHORT_3_NAME);
        
        private String cohortName;
        private int cohortNum;

        private CohortVariable(int cohortNum2, String cohortName2) {
            this.cohortNum = cohortNum2;
            this.cohortName = cohortName2;
        }

        public String toString() {
            return this.cohortName;
        }

        public int toInteger() {
            return this.cohortNum;
        }
    }

    void addToCart(Context context, IgawCommerceProductModel igawCommerceProductModel);

    void addToCart(Context context, IgawCommerceProductModel igawCommerceProductModel, Map<String, String> map);

    void addToCartBulk(Context context, List<IgawCommerceProductModel> list);

    void addToCartBulk(Context context, List<IgawCommerceProductModel> list, Map<String, String> map);

    void addToWishList(Context context, IgawCommerceProductModel igawCommerceProductModel);

    void addToWishList(Context context, IgawCommerceProductModel igawCommerceProductModel, Map<String, String> map);

    void appOpen(Context context);

    void appOpen(Context context, Map<String, String> map);

    void buy(String str);

    void buy(String str, String str2);

    void categoryView(Context context, IgawCommerceProductCategoryModel igawCommerceProductCategoryModel);

    void categoryView(Context context, IgawCommerceProductCategoryModel igawCommerceProductCategoryModel, List<IgawCommerceProductModel> list);

    void categoryView(Context context, IgawCommerceProductCategoryModel igawCommerceProductCategoryModel, List<IgawCommerceProductModel> list, Map<String, String> map);

    void categoryView(Context context, IgawCommerceProductCategoryModel igawCommerceProductCategoryModel, Map<String, String> map);

    void deeplinkOpen(Context context, String str);

    void deeplinkOpen(Context context, String str, Map<String, String> map);

    void firstTimeExperience(String str);

    void firstTimeExperience(String str, String str2);

    void flush();

    void hideAD();

    void login(Context context, String str);

    void login(Context context, String str, Map<String, String> map);

    void paymentView(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2);

    void paymentView(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2, Map<String, String> map);

    void productView(Context context, IgawCommerceProductModel igawCommerceProductModel);

    void productView(Context context, IgawCommerceProductModel igawCommerceProductModel, Map<String, String> map);

    void purchase(Context context, String str);

    void purchase(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Double d2, IgawPaymentMethod igawPaymentMethod);

    void purchase(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Double d2, IgawPaymentMethod igawPaymentMethod, Map<String, String> map);

    void purchase(Context context, String str, Double d, Currency currency, IgawPaymentMethod igawPaymentMethod);

    void purchase(Context context, String str, Double d, Currency currency, IgawPaymentMethod igawPaymentMethod, Map<String, String> map);

    void purchase(Context context, String str, String str2, String str3, double d, int i, Currency currency, String str4);

    void purchase(Context context, List<IgawCommerceItemModel> list);

    void purchaseBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2, IgawPaymentMethod igawPaymentMethod);

    void purchaseBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2, IgawPaymentMethod igawPaymentMethod, Map<String, String> map);

    void refund(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d);

    void refund(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Map<String, String> map);

    void refundBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d);

    void refundBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Map<String, String> map);

    void retention(String str);

    void retention(String str, String str2);

    void reviewOrder(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Double d2);

    void reviewOrder(Context context, String str, IgawCommerceProductModel igawCommerceProductModel, Double d, Double d2, Map<String, String> map);

    void reviewOrderBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2);

    void reviewOrderBulk(Context context, String str, List<IgawCommerceProductModel> list, Double d, Double d2, Map<String, String> map);

    void search(Context context, String str, List<IgawCommerceProductModel> list);

    void search(Context context, String str, List<IgawCommerceProductModel> list, Map<String, String> map);

    void setCustomCohort(CohortVariable cohortVariable, String str);

    void setDemographic(String str, String str2);

    void share(Context context, IgawSharingChannel igawSharingChannel, IgawCommerceProductModel igawCommerceProductModel);

    void share(Context context, IgawSharingChannel igawSharingChannel, IgawCommerceProductModel igawCommerceProductModel, Map<String, String> map);

    void showAD(String str, Activity activity);

    void showAD(String str, Activity activity, ADBrixCallbackListener aDBrixCallbackListener);

    void showAD(String str, Activity activity, PromotionActionListener promotionActionListener);

    void useCoupon(String str);
}