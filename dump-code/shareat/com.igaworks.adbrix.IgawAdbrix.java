package com.igaworks.adbrix;

import android.content.Context;
import android.util.Log;
import com.igaworks.IgawCommon;
import com.igaworks.adbrix.core.ADBrixUpdateLog;
import com.igaworks.adbrix.impl.ADBrixFrameworkFactory;
import com.igaworks.adbrix.interfaces.ADBrixInterface;
import com.igaworks.adbrix.interfaces.ADBrixInterface.CohortVariable;
import com.igaworks.commerce.IgawCommerce.IgawPaymentMethod;
import com.igaworks.commerce.IgawCommerce.IgawSharingChannel;
import com.igaworks.commerce.IgawCommerceItemModel;
import com.igaworks.commerce.IgawCommerceProductCategoryModel;
import com.igaworks.commerce.IgawCommerceProductModel;
import com.igaworks.core.IgawConstant;
import com.igaworks.impl.CommonFrameworkFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;

public class IgawAdbrix {
    private static ADBrixInterface adbrixFrameWork;

    public static class Commerce {
        public static void purchase(Context context, String productID, Double price, Currency currency, IgawPaymentMethod paymentMethod) {
            try {
                IgawAdbrix.framework().purchase(context, productID, price, com.igaworks.commerce.IgawCommerce.Currency.getCurrencyByCountryCode(currency.getCountry()), IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()));
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase I error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void purchase(Context context, String productID, Double price, com.igaworks.commerce.IgawCommerce.Currency currency, IgawPaymentMethod paymentMethod) {
            try {
                IgawAdbrix.framework().purchase(context, productID, price, com.igaworks.commerce.IgawCommerce.Currency.getCurrencyByCountryCode(currency.getCountry()), IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()));
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase I error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void purchase(Context context, String orderID, IgawCommerceProductModel purchaseDetail, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod) {
            try {
                IgawAdbrix.framework().purchase(context, orderID, purchaseDetail, discount, deliveryCharge, IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()));
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase II error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void purchaseBulk(Context context, String orderID, List<IgawCommerceProductModel> purchaseList, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod) {
            try {
                IgawAdbrix.framework().purchaseBulk(context, orderID, purchaseList, discount, deliveryCharge, IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()));
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase III error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void deeplinkOpen(Context context, String deeplinkUrl) {
            try {
                IgawAdbrix.framework().deeplinkOpen(context, deeplinkUrl);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.deeplinkOpen error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void productView(Context context, IgawCommerceProductModel product) {
            try {
                IgawAdbrix.framework().productView(context, product);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.productView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void refund(Context context, String orderId, IgawCommerceProductModel product, Double penaltyCharge) {
            try {
                IgawAdbrix.framework().refund(context, orderId, product, penaltyCharge);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.refund error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void refundBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double penaltyCharge) {
            try {
                IgawAdbrix.framework().refundBulk(context, orderId, products, penaltyCharge);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.refund_bulk error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void addToCart(Context context, IgawCommerceProductModel product) {
            try {
                IgawAdbrix.framework().addToCart(context, product);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.addToCart error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void addToCartBulk(Context context, List<IgawCommerceProductModel> products) {
            try {
                IgawAdbrix.framework().addToCartBulk(context, products);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.addToCartBulk error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void login(Context context, String usn) {
            try {
                IgawAdbrix.framework().login(context, usn);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.login error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void addToWishList(Context context, IgawCommerceProductModel product) {
            try {
                IgawAdbrix.framework().addToWishList(context, product);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.addToWishList error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void categoryView(Context context, IgawCommerceProductCategoryModel category) {
            try {
                IgawAdbrix.framework().categoryView(context, category);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.categoryView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void categoryView(Context context, IgawCommerceProductCategoryModel category, List<IgawCommerceProductModel> products) {
            try {
                IgawAdbrix.framework().categoryView(context, category, products);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.categoryView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void reviewOrder(Context context, String orderId, IgawCommerceProductModel product, Double discount, Double deliveryCharge) {
            try {
                IgawAdbrix.framework().reviewOrder(context, orderId, product, discount, deliveryCharge);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.categoryView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void reviewOrderBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, double deliveryCharge) {
            try {
                IgawAdbrix.framework().reviewOrderBulk(context, orderId, products, discount, Double.valueOf(deliveryCharge));
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.categoryView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void paymentView(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge) {
            try {
                IgawAdbrix.framework().paymentView(context, orderId, products, discount, deliveryCharge);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.paymentView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void search(Context context, String keyword, List<IgawCommerceProductModel> resultProducts) {
            try {
                IgawAdbrix.framework().search(context, keyword, resultProducts);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.paymentView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void share(Context context, IgawSharingChannel sharingChennel, IgawCommerceProductModel product) {
            try {
                IgawAdbrix.framework().share(context, IgawSharingChannel.getChannelByChannelCode(sharingChennel.getChannel()), product);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.paymentView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void purchase(Context context, String productID, Double price, Currency currency, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().purchase(context, productID, price, com.igaworks.commerce.IgawCommerce.Currency.getCurrencyByCountryCode(currency.getCountry()), IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()), attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase I error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void purchase(Context context, String productID, Double price, com.igaworks.commerce.IgawCommerce.Currency currency, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().purchase(context, productID, price, com.igaworks.commerce.IgawCommerce.Currency.getCurrencyByCountryCode(currency.getCountry()), IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()), attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase I error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void purchase(Context context, String orderID, IgawCommerceProductModel purchaseDetail, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().purchase(context, orderID, purchaseDetail, discount, deliveryCharge, IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()), attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase II error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void purchaseBulk(Context context, String orderID, List<IgawCommerceProductModel> purchaseList, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().purchaseBulk(context, orderID, purchaseList, discount, deliveryCharge, IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()), attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase III error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void deeplinkOpen(Context context, String deeplinkUrl, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().deeplinkOpen(context, deeplinkUrl, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.deeplinkOpen error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void productView(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().productView(context, product, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.productView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void refund(Context context, String orderId, IgawCommerceProductModel product, Double penaltyCharge, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().refund(context, orderId, product, penaltyCharge, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.refund error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void refundBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double penaltyCharge, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().refundBulk(context, orderId, products, penaltyCharge, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.refund_bulk error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void addToCart(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().addToCart(context, product, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.addToCart error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void addToCartBulk(Context context, List<IgawCommerceProductModel> products, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().addToCartBulk(context, products, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.addToCartBulk error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void login(Context context, String usn, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().login(context, usn, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.login error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void addToWishList(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().addToWishList(context, product, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.addToWishList error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void categoryView(Context context, IgawCommerceProductCategoryModel category, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().categoryView(context, category, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.categoryView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void categoryView(Context context, IgawCommerceProductCategoryModel category, List<IgawCommerceProductModel> products, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().categoryView(context, category, products, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.categoryView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void reviewOrder(Context context, String orderId, IgawCommerceProductModel product, Double discount, Double deliveryCharge, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().reviewOrder(context, orderId, product, discount, deliveryCharge, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.categoryView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void reviewOrderBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, double deliveryCharge, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().reviewOrderBulk(context, orderId, products, discount, Double.valueOf(deliveryCharge), attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.categoryView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void paymentView(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().paymentView(context, orderId, products, discount, deliveryCharge, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.paymentView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void search(Context context, String keyword, List<IgawCommerceProductModel> resultProducts, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().search(context, keyword, resultProducts, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.paymentView error: " + e.getMessage());
                e.printStackTrace();
            }
        }

        public static void share(Context context, IgawSharingChannel sharingChennel, IgawCommerceProductModel product, Map<String, String> attrData) {
            try {
                IgawAdbrix.framework().share(context, IgawSharingChannel.getChannelByChannelCode(sharingChennel.getChannel()), product, attrData);
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.paymentView error: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    @Deprecated
    public static class Currency {
        public static final Currency CN_CNY = new Currency("CN", "CNY");
        public static final Currency EU_EUR = new Currency("EU", "EUR");
        public static final Currency HK_HKD = new Currency("HK", "HKD");
        public static final Currency JP_JPY = new Currency("JP", "JPY");
        public static final Currency KR_KRW = new Currency("KR", "KRW");
        public static final Currency TW_TWD = new Currency("TW", "TWD");
        public static final Currency UK_GBP = new Currency("UK", "GBP");
        public static final Currency US_USD = new Currency("US", "USD");
        private String code;
        private String country;

        private Currency(String country2, String code2) {
            this.country = country2;
            this.code = code2;
        }

        public String getCode() {
            return this.code;
        }

        public void setCode(String code2) {
            this.code = code2;
        }

        public String getCountry() {
            return this.country;
        }

        public void setCountry(String country2) {
            this.country = country2;
        }

        public static Currency getCurrencyByCurrencyCode(String currencyCode) {
            if (currencyCode.equalsIgnoreCase(KR_KRW.toString())) {
                return KR_KRW;
            }
            if (currencyCode.equalsIgnoreCase(US_USD.toString())) {
                return US_USD;
            }
            if (currencyCode.equalsIgnoreCase(JP_JPY.toString())) {
                return JP_JPY;
            }
            if (currencyCode.equalsIgnoreCase(EU_EUR.toString())) {
                return EU_EUR;
            }
            if (currencyCode.equalsIgnoreCase(UK_GBP.toString())) {
                return UK_GBP;
            }
            if (currencyCode.equalsIgnoreCase(CN_CNY.toString())) {
                return CN_CNY;
            }
            if (currencyCode.equalsIgnoreCase(TW_TWD.toString())) {
                return TW_TWD;
            }
            if (currencyCode.equalsIgnoreCase(HK_HKD.toString())) {
                return HK_HKD;
            }
            return new Currency(currencyCode, currencyCode);
        }

        public static Currency getCurrencyByCountryCode(String countryCode) {
            if (countryCode.equalsIgnoreCase(KR_KRW.getCountry())) {
                return KR_KRW;
            }
            if (countryCode.equalsIgnoreCase(US_USD.getCountry())) {
                return US_USD;
            }
            if (countryCode.equalsIgnoreCase(JP_JPY.getCountry())) {
                return JP_JPY;
            }
            if (countryCode.equalsIgnoreCase(EU_EUR.getCountry())) {
                return EU_EUR;
            }
            if (countryCode.equalsIgnoreCase(UK_GBP.getCountry())) {
                return UK_GBP;
            }
            if (countryCode.equalsIgnoreCase(CN_CNY.getCountry())) {
                return CN_CNY;
            }
            if (countryCode.equalsIgnoreCase(TW_TWD.getCountry())) {
                return TW_TWD;
            }
            if (countryCode.equalsIgnoreCase(HK_HKD.getCountry())) {
                return HK_HKD;
            }
            return new Currency(countryCode, countryCode);
        }

        public String toString() {
            return this.code;
        }
    }

    static {
        try {
            ADBrixUpdateLog.updateVersion();
        } catch (Exception e) {
        }
    }

    /* access modifiers changed from: private */
    public static ADBrixInterface framework() {
        if (adbrixFrameWork == null) {
            adbrixFrameWork = ADBrixFrameworkFactory.getFramework();
        }
        if (IgawCommon.igawPubQueue == null || IgawCommon.igawPubQueue.isShutdown()) {
            IgawCommon.igawPubQueue = Executors.newSingleThreadExecutor();
        }
        CommonFrameworkFactory.isHasAdbrixSDK = true;
        return adbrixFrameWork;
    }

    public static void firstTimeExperience(final String name) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().firstTimeExperience(name);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void firstTimeExperience(final String name, final String param) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().firstTimeExperience(name, param);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void buy(final String name) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().buy(name);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void flush() {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().flush();
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void buy(final String name, final String param) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().buy(name, param);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void setDemographic(final String key, final String value) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().setDemographic(key, value);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void retention(final String name) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().retention(name);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void retention(final String name, final String param) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().retention(name, param);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void setAge(final int age) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().setAge(age);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void setGender(final int gender) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().setGender(gender);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void setCustomCohort(final CohortVariable cohortVariable, final String cohort) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().setCustomCohort(CohortVariable.this, cohort);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void useCoupon(final String coupon) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().useCoupon(coupon);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void viral(final String name) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().viral(name);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void viral(final String name, final String param) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().viral(name, param);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void error(final String errorName, final String detail) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().error(errorName, detail);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void custom(final String name) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().custom(name);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void custom(final String name, final String param) {
        try {
            IgawCommon.igawPubQueue.execute(new Runnable() {
                public void run() {
                    IgawAdbrix.framework().custom(name, param);
                }
            });
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void purchase(Context context, String orderID, String productID, String productName, double price, int quantity, Currency currency, String category) {
        try {
            framework().purchase(context, orderID, productID, productName, price, quantity, com.igaworks.commerce.IgawCommerce.Currency.getCurrencyByCountryCode(currency.getCountry()), category);
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "Adbrix.purchase error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void purchase(Context context, String orderID, String productID, String productName, double price, int quantity, com.igaworks.commerce.IgawCommerce.Currency currency, String category) {
        try {
            framework().purchase(context, orderID, productID, productName, price, quantity, com.igaworks.commerce.IgawCommerce.Currency.getCurrencyByCountryCode(currency.getCountry()), category);
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "Adbrix.purchase error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @Deprecated
    public static void purchase(Context context, List<PurchaseItemModel> purchaseList) {
        if (purchaseList != null) {
            try {
                if (purchaseList.size() != 0) {
                    List<IgawCommerceItemModel> igawCommerceItemList = new ArrayList<>();
                    for (PurchaseItemModel item : purchaseList) {
                        igawCommerceItemList.add(IgawCommerceItemModel.create(item.orderId, item.productId, item.productName, item.price, item.quantity, com.igaworks.commerce.IgawCommerce.Currency.getCurrencyByCountryCode(item.currency.getCountry()), item.category));
                    }
                    framework().purchase(context, igawCommerceItemList);
                    return;
                }
            } catch (Exception e) {
                Log.e(IgawConstant.QA_TAG, "Adbrix.purchase error: " + e.getMessage());
                e.printStackTrace();
                return;
            }
        }
        Log.i(IgawConstant.QA_TAG, "Adbrix.purchase >> Null or empty purchaseList");
    }

    @Deprecated
    public static void purchase(Context context, String purchaseDataJsonString) {
        framework().purchase(context, purchaseDataJsonString);
    }

    public static void purchase(Context context, String productID, Double price, com.igaworks.commerce.IgawCommerce.Currency currency, IgawPaymentMethod paymentMethod) {
        try {
            framework().purchase(context, productID, price, com.igaworks.commerce.IgawCommerce.Currency.getCurrencyByCountryCode(currency.getCountry()), IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()));
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase I error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void purchase(Context context, String orderID, IgawCommerceProductModel purchaseDetail, IgawPaymentMethod paymentMethod) {
        try {
            Context context2 = context;
            String str = orderID;
            IgawCommerceProductModel igawCommerceProductModel = purchaseDetail;
            framework().purchase(context2, str, igawCommerceProductModel, Double.valueOf(0.0d), Double.valueOf(0.0d), IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()));
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase II error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void purchaseBulk(Context context, String orderID, List<IgawCommerceProductModel> purchaseList, IgawPaymentMethod paymentMethod) {
        try {
            Context context2 = context;
            String str = orderID;
            List<IgawCommerceProductModel> list = purchaseList;
            framework().purchaseBulk(context2, str, list, Double.valueOf(0.0d), Double.valueOf(0.0d), IgawPaymentMethod.getMethodByMethodCode(paymentMethod.getMethod()));
        } catch (Exception e) {
            Log.e(IgawConstant.QA_TAG, "Adbrix.Commerce.purchase III error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}