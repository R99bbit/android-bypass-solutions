package com.igaworks.commerce;

import android.content.Context;
import com.igaworks.commerce.core.CommerceUpdateLog;
import com.igaworks.commerce.impl.CommerceFrameworkFactory;
import com.igaworks.commerce.interfaces.CommerceInterface;
import java.util.List;
import java.util.Map;

public class IgawCommerce {
    private static CommerceInterface adbrixFrameWork;

    public static class Currency {
        public static final Currency CN_CNY = new Currency("CH", "CNY");
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

    public static class IgawPaymentMethod {
        public static final IgawPaymentMethod BankTransfer = new IgawPaymentMethod("BankTransfer");
        public static final IgawPaymentMethod CreditCard = new IgawPaymentMethod("CreditCard");
        public static final IgawPaymentMethod ETC = new IgawPaymentMethod("ETC");
        public static final IgawPaymentMethod MobilePayment = new IgawPaymentMethod("MobilePayment");
        private String method;

        public IgawPaymentMethod(String method2) {
            this.method = method2;
        }

        public String getMethod() {
            return this.method;
        }

        public void setMethod(String method2) {
            this.method = method2;
        }

        public static IgawPaymentMethod getMethodByMethodCode(String mehod) {
            if (mehod.equalsIgnoreCase(CreditCard.getMethod())) {
                return CreditCard;
            }
            if (mehod.equalsIgnoreCase(BankTransfer.getMethod())) {
                return BankTransfer;
            }
            if (mehod.equalsIgnoreCase(MobilePayment.getMethod())) {
                return MobilePayment;
            }
            if (mehod.equalsIgnoreCase(ETC.getMethod())) {
                return ETC;
            }
            return new IgawPaymentMethod(mehod);
        }

        public String toString() {
            return this.method;
        }
    }

    public static class IgawSharingChannel {
        public static final IgawSharingChannel ETC = new IgawSharingChannel("ETC");
        public static final IgawSharingChannel Email = new IgawSharingChannel("Email");
        public static final IgawSharingChannel Facebook = new IgawSharingChannel("Facebook");
        public static final IgawSharingChannel KakaoStory = new IgawSharingChannel("KakaoStory");
        public static final IgawSharingChannel KakaoTalk = new IgawSharingChannel("KakaoTalk");
        public static final IgawSharingChannel Line = new IgawSharingChannel("Line");
        public static final IgawSharingChannel QQ = new IgawSharingChannel("QQ");
        public static final IgawSharingChannel SMS = new IgawSharingChannel("SMS");
        public static final IgawSharingChannel WeChat = new IgawSharingChannel("WeChat");
        public static final IgawSharingChannel copyUrl = new IgawSharingChannel("copyUrl");
        public static final IgawSharingChannel whatsApp = new IgawSharingChannel("whatsApp");
        private String channel;

        public IgawSharingChannel(String channel2) {
            this.channel = channel2;
        }

        public String getChannel() {
            return this.channel;
        }

        public void setChannel(String channel2) {
            this.channel = channel2;
        }

        public static IgawSharingChannel getChannelByChannelCode(String channel2) {
            if (channel2.equalsIgnoreCase(Facebook.getChannel())) {
                return Facebook;
            }
            if (channel2.equalsIgnoreCase(KakaoTalk.getChannel())) {
                return KakaoTalk;
            }
            if (channel2.equalsIgnoreCase(KakaoStory.getChannel())) {
                return KakaoStory;
            }
            if (channel2.equalsIgnoreCase(Line.getChannel())) {
                return Line;
            }
            if (channel2.equalsIgnoreCase(whatsApp.getChannel())) {
                return whatsApp;
            }
            if (channel2.equalsIgnoreCase(QQ.getChannel())) {
                return QQ;
            }
            if (channel2.equalsIgnoreCase(WeChat.getChannel())) {
                return WeChat;
            }
            if (channel2.equalsIgnoreCase(SMS.getChannel())) {
                return SMS;
            }
            if (channel2.equalsIgnoreCase(Email.getChannel())) {
                return Email;
            }
            if (channel2.equalsIgnoreCase(copyUrl.getChannel())) {
                return copyUrl;
            }
            if (channel2.equalsIgnoreCase(ETC.getChannel())) {
                return ETC;
            }
            return new IgawSharingChannel(channel2);
        }

        public String toString() {
            return this.channel;
        }
    }

    static {
        try {
            CommerceUpdateLog.updateVersion();
        } catch (Exception e) {
        }
    }

    private static CommerceInterface framework() {
        if (adbrixFrameWork == null) {
            adbrixFrameWork = CommerceFrameworkFactory.getFramework();
        }
        return adbrixFrameWork;
    }

    public static void purchase(Context context, String orderID, String productId, String productName, double price, int quantity, Currency currency, String category) {
        framework().purchase(context, orderID, productId, productName, price, quantity, currency.toString(), category);
    }

    public static void purchase(Context context, List<IgawCommerceItemModel> purchaseItems) {
        framework().purchase(context, purchaseItems);
    }

    public static void purchase(Context context, String purchaseDataJsonString) {
        framework().purchase(context, purchaseDataJsonString);
    }

    public static void home(Context context) {
        framework().home(context);
    }

    public static void login(Context context, String usn, String hashedEmail) {
        framework().login(context, usn, hashedEmail);
    }

    public static void logout(Context context) {
        framework().logout(context);
    }

    public static void category(Context context, String catID) {
        framework().category(context, catID);
    }

    public static void subCategory(Context context, String subCat1ID) {
        framework().subCategory(context, subCat1ID);
    }

    public static void subSubCategory(Context context, String subCat2ID) {
        framework().subSubCategory(context, subCat2ID);
    }

    public static void productDetail(Context context, String pid) {
        framework().productDetail(context, pid);
    }

    public static void shoppingCart(Context context, String pid1, int quantity1, String pid2, int quantity2, String pid3, int quantity3, Currency currency) {
        framework().shoppingCart(context, pid1, quantity1, pid2, quantity2, pid3, quantity3, currency);
    }

    public static void orderReview(Context context, String pid1, int quantity1, String pid2, int quantity2, String pid3, int quantity3, Currency currency) {
        framework().orderReview(context, pid1, quantity1, pid2, quantity2, pid3, quantity3, currency);
    }

    public static void paymentModeSelection(Context context, String pid1, int quantity1, String pid2, int quantity2, String pid3, int quantity3, Currency currency) {
        framework().paymentModeSelection(context, pid1, quantity1, pid2, quantity2, pid3, quantity3, currency);
    }

    public static void orderConfirmation(Context context, String orderID, long orderPrice, String pid1, String pid2, String pid3) {
        framework().orderConfirmation(context, orderID, orderPrice, pid1, pid2, pid3);
    }

    public static void wishList(Context context, String pid1, int quantity1, String pid2, int quantity2, String pid3, int quantity3, Currency currency) {
        framework().wishList(context, pid1, quantity1, pid2, quantity2, pid3, quantity3, currency);
    }

    public static void purchase(Context context, String productID, Double price, Currency currency, IgawPaymentMethod paymentMethod) {
        framework().purchase(context, productID, price, currency, paymentMethod);
    }

    public static void purchase(Context context, String orderID, IgawCommerceProductModel purchaseDetail, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod) {
        framework().purchase(context, orderID, purchaseDetail, discount, deliveryCharge, paymentMethod);
    }

    public static void purchase(Context context, String orderID, List<IgawCommerceProductModel> purchaseList, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod) {
        framework().purchaseBulk(context, orderID, purchaseList, discount, deliveryCharge, paymentMethod);
    }

    public static void appOpen(Context context) {
        framework().appOpen(context);
    }

    public static void deeplinkOpen(Context context, String deeplinkUrl) {
        framework().deeplinkOpen(context, deeplinkUrl);
    }

    public static void login(Context context) {
        framework().login(context);
    }

    public static void refund(Context context, String orderId, IgawCommerceProductModel product, Double penaltyCharge) {
        framework().refund(context, orderId, product, penaltyCharge);
    }

    public static void refundBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double penaltyCharge) {
        framework().refundBulk(context, orderId, products, penaltyCharge);
    }

    public static void addToCart(Context context, IgawCommerceProductModel product) {
        framework().addToCart(context, product);
    }

    public static void addToCartBulk(Context context, List<IgawCommerceProductModel> products) {
        framework().addToCartBulk(context, products);
    }

    public static void addToWishList(Context context, IgawCommerceProductModel product) {
        framework().addToWishList(context, product);
    }

    public static void productView(Context context, IgawCommerceProductModel product) {
        framework().productView(context, product);
    }

    public static void categoryView(Context context, IgawCommerceProductCategoryModel category) {
        framework().categoryView(context, category);
    }

    public static void categoryView(Context context, IgawCommerceProductCategoryModel category, List<IgawCommerceProductModel> products) {
        framework().categoryView(context, category, products);
    }

    public static void reviewOrder(Context context, String orderId, IgawCommerceProductModel product, Double discount, Double deliveryCharge) {
        framework().reviewOrder(context, orderId, product, discount, deliveryCharge);
    }

    public static void reviewOrderBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge) {
        framework().reviewOrderBulk(context, orderId, products, discount, deliveryCharge);
    }

    public static void paymentView(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge) {
        framework().paymentView(context, orderId, products, discount, deliveryCharge);
    }

    public static void search(Context context, String keyword, List<IgawCommerceProductModel> resultProducts) {
        framework().search(context, keyword, resultProducts);
    }

    public static void share(Context context, IgawSharingChannel sharingChennel, IgawCommerceProductModel product) {
        framework().share(context, sharingChennel, product);
    }

    public static void purchase(Context context, String productID, Double price, Currency currency, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
        framework().purchase(context, productID, price, currency, paymentMethod, attrData);
    }

    public static void purchase(Context context, String orderID, IgawCommerceProductModel purchaseDetail, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
        framework().purchase(context, orderID, purchaseDetail, discount, deliveryCharge, paymentMethod, attrData);
    }

    public static void purchase(Context context, String orderID, List<IgawCommerceProductModel> purchaseList, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
        framework().purchaseBulk(context, orderID, purchaseList, discount, deliveryCharge, paymentMethod, attrData);
    }

    public static void appOpen(Context context, Map<String, String> attrData) {
        framework().appOpen(context, attrData);
    }

    public static void deeplinkOpen(Context context, String deeplinkUrl, Map<String, String> attrData) {
        framework().deeplinkOpen(context, deeplinkUrl, attrData);
    }

    public static void login(Context context, Map<String, String> attrData) {
        framework().login(context, attrData);
    }

    public static void refund(Context context, String orderId, IgawCommerceProductModel product, Double penaltyCharge, Map<String, String> attrData) {
        framework().refund(context, orderId, product, penaltyCharge, attrData);
    }

    public static void refundBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double penaltyCharge, Map<String, String> attrData) {
        framework().refundBulk(context, orderId, products, penaltyCharge, attrData);
    }

    public static void addToCart(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
        framework().addToCart(context, product, attrData);
    }

    public static void addToCartBulk(Context context, List<IgawCommerceProductModel> products, Map<String, String> attrData) {
        framework().addToCartBulk(context, products, attrData);
    }

    public static void addToWishList(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
        framework().addToWishList(context, product, attrData);
    }

    public static void productView(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
        framework().productView(context, product, attrData);
    }

    public static void categoryView(Context context, IgawCommerceProductCategoryModel category, Map<String, String> attrData) {
        framework().categoryView(context, category, attrData);
    }

    public static void categoryView(Context context, IgawCommerceProductCategoryModel category, List<IgawCommerceProductModel> products, Map<String, String> attrData) {
        framework().categoryView(context, category, products, attrData);
    }

    public static void reviewOrder(Context context, String orderId, IgawCommerceProductModel product, Double discount, Double deliveryCharge, Map<String, String> attrData) {
        framework().reviewOrder(context, orderId, product, discount, deliveryCharge, attrData);
    }

    public static void reviewOrderBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge, Map<String, String> attrData) {
        framework().reviewOrderBulk(context, orderId, products, discount, deliveryCharge, attrData);
    }

    public static void paymentView(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge, Map<String, String> attrData) {
        framework().paymentView(context, orderId, products, discount, deliveryCharge, attrData);
    }

    public static void search(Context context, String keyword, List<IgawCommerceProductModel> resultProducts, Map<String, String> attrData) {
        framework().search(context, keyword, resultProducts, attrData);
    }

    public static void share(Context context, IgawSharingChannel sharingChennel, IgawCommerceProductModel product, Map<String, String> attrData) {
        framework().share(context, sharingChennel, product, attrData);
    }
}