package com.igaworks.commerce.impl;

import android.content.Context;
import android.util.Log;
import android.util.Pair;
import com.igaworks.commerce.IgawCommerce.Currency;
import com.igaworks.commerce.IgawCommerce.IgawPaymentMethod;
import com.igaworks.commerce.IgawCommerce.IgawSharingChannel;
import com.igaworks.commerce.IgawCommerceItemModel;
import com.igaworks.commerce.IgawCommerceProductCategoryModel;
import com.igaworks.commerce.IgawCommerceProductModel;
import com.igaworks.commerce.db.CommerceDB;
import com.igaworks.commerce.db.CommerceEventDAO;
import com.igaworks.commerce.db.CommerceEventV2DAO;
import com.igaworks.commerce.db.DemographicDAO;
import com.igaworks.commerce.db.PurchaseRetryDAO;
import com.igaworks.commerce.interfaces.CommerceInterface;
import com.igaworks.commerce.model.CommerceV2EventItem;
import com.igaworks.commerce.model.CustomEventModel;
import com.igaworks.commerce.model.PurchaseItem;
import com.igaworks.commerce.net.CommerceHttpManager;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.impl.CommonFrameworkImpl;
import com.igaworks.interfaces.ExtendedCommonActivityListener;
import com.igaworks.util.CommonHelper;
import com.igaworks.util.bolts_task.Task;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.UUID;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

public class CommerceImpl implements CommerceInterface, ExtendedCommonActivityListener {
    public static final String CATEGORY_EVENT = "category";
    public static final String CV2_ADD_TO_CART = "add_to_cart";
    public static final String CV2_ADD_TO_WISHLIST = "add_to_wishlist";
    public static final String CV2_APP_OPEN = "app_open";
    public static final String CV2_CATEGORY_VIEW = "category_view";
    public static final String CV2_DEEPLINK_OPEN = "deeplink_open";
    public static final String CV2_LOGIN = "login";
    public static final String CV2_PAYMENT_VIEW = "payment_view";
    public static final String CV2_PRDUCT_VIEW = "product_view";
    public static final String CV2_PURCHASE = "purchase";
    public static final String CV2_REFUND = "refund";
    public static final String CV2_REVIEW_ORDER = "review_order";
    public static final String CV2_SERACH = "search";
    public static final String CV2_SHARE = "share";
    public static final int DOMAIN_AB4C = 0;
    public static final int DOMAIN_NEW_COMMERCEV2 = 1;
    public static final String HOME_EVENT = "home";
    public static final String LOGIN_EVENT = "login";
    public static final String LOGOUT_EVENT = "logout";
    public static final String ORDER_CONFIRMATION_EVENT = "orderConfirmation";
    public static final String ORDER_REVIEW_EVENT = "orderReview";
    public static final String PAYMENT_MODE_EVENT = "paymentModeSelection";
    public static final String PRODUCT_DETAIL_EVENT = "productDetail";
    public static final String SHOPPING_CART_EVENT = "shoppingCart";
    public static final String SUB_CATEGORY_EVENT = "subCategory";
    public static final String SUB_SUB_CATEGORY_EVENT = "subSubCategory";
    public static final String WISH_LIST_EVENT = "wishList";
    /* access modifiers changed from: private */
    public static CommerceHttpManager httpManager = new CommerceHttpManager();

    enum ApiCommerce {
        ENUM_APP_OPEN,
        ENUM_DEEPLINK_OPEN,
        ENUM_LOGIN,
        ENUM_REFUND,
        ENUM_ADD_TO_CART,
        ENUM_ADD_TO_WISHLIST,
        ENUM_PRDUCT_VIEW,
        ENUM_CATEGORY_VIEW,
        ENUM_REVIEW_ORDER,
        ENUM_PAYMENT_VIEW,
        ENUM_SERACH,
        ENUM_SHARE
    }

    protected CommerceImpl() {
    }

    public void purchase(Context context, String orderID, String productID, String productName, double price, int quantity, String currency, String category) {
        try {
            ArrayList<PurchaseItem> items = new ArrayList<>();
            items.add(new PurchaseItem(-1, orderID, productID, productName, price, quantity, currency, category, new StringBuilder(String.valueOf(new Date().getTime())).toString(), 0));
            httpManager.purchaseForCommerce(RequestParameter.getATRequestParameter(context), context, items);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void purchase(Context context, List<IgawCommerceItemModel> purchaseList) {
        try {
            ArrayList<PurchaseItem> items = new ArrayList<>();
            for (IgawCommerceItemModel item : purchaseList) {
                items.add(new PurchaseItem(-1, item.getOrderID(), item.getProductID(), item.getProductName(), item.getPrice(), item.getQuantity(), item.getCurrency().toString(), item.getCategory(), new StringBuilder(String.valueOf(new Date().getTime())).toString(), 0));
            }
            httpManager.purchaseForCommerce(RequestParameter.getATRequestParameter(context), context, items);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void purchase(Context context, String purchaseDataJsonString) {
        String currency;
        int quantity;
        try {
            JSONArray jSONArray = new JSONArray(purchaseDataJsonString);
            if (jSONArray.length() < 1) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "purchase error : No purhcase item.", 0, false);
                return;
            }
            ArrayList<PurchaseItem> items = new ArrayList<>();
            int i = 0;
            while (i < jSONArray.length()) {
                try {
                    JSONObject item = jSONArray.getJSONObject(i);
                    String orderID = "";
                    String productName = "";
                    String category = "";
                    if (item.has("orderId")) {
                        orderID = item.getString("orderId");
                    }
                    if (item.has("productId")) {
                        String productID = item.getString("productId");
                        if (item.has("productName")) {
                            productName = item.getString("productName");
                        }
                        if (item.has("price")) {
                            double price = item.getDouble("price");
                            if (item.has("currency")) {
                                currency = Currency.getCurrencyByCurrencyCode(item.getString("currency")).getCode();
                            } else {
                                currency = Currency.KR_KRW.getCode();
                            }
                            if (item.has("quantity")) {
                                quantity = item.getInt("quantity");
                            } else {
                                quantity = 1;
                            }
                            if (item.has("category")) {
                                category = item.getString("category");
                            }
                            items.add(new PurchaseItem(-1, orderID, productID, productName, price, quantity, currency, category, new StringBuilder(String.valueOf(new Date().getTime())).toString(), 0));
                            i++;
                        } else {
                            throw new Exception("No price attribute.");
                        }
                    } else {
                        throw new Exception("No productId attribute.");
                    }
                } catch (Exception e) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "purchase error : invalid item = " + purchaseDataJsonString, 0, false);
                }
            }
            if (items == null || items.size() < 1) {
                throw new Exception("No purchase item.");
            }
            httpManager.purchaseForCommerce(RequestParameter.getATRequestParameter(context), context, items);
        } catch (Exception e2) {
            e2.printStackTrace();
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "purchase error : " + e2.toString(), 0, false);
        }
    }

    public void fireEvent(final Context context, final CustomEventModel model) {
        Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
            public void run() {
                try {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "eventFired >> " + model.toString(), 2, false);
                    CommerceEventDAO.addEvent(context, model.toString());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    public void fireEvent(final Context context, final String json) {
        if (json == null) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "eventFired >> event is null", 0, false);
        }
        Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
            public void run() {
                try {
                    Log.i(IgawConstant.QA_TAG, "Commerce >> purchase for commerceV2--fireEvent--1" + json);
                    CommerceEventV2DAO.addEvent(context, json);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        });
    }

    public void home(Context context) {
        fireEvent(context, new CustomEventModel(HOME_EVENT, null, new Date().getTime()));
    }

    public void login(Context context, String usn, String hashedEmail) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("usn", usn));
        params.add(new Pair("emailhash", hashedEmail));
        fireEvent(context, new CustomEventModel("login", params, new Date().getTime()));
        DemographicDAO.saveDemographic(CommonFrameworkImpl.getContext(), DemographicDAO.KEY_USN, usn);
        DemographicDAO.saveDemographic(CommonFrameworkImpl.getContext(), "email", hashedEmail);
    }

    public void logout(Context context) {
        fireEvent(context, new CustomEventModel(LOGOUT_EVENT, null, new Date().getTime()));
    }

    public void category(Context context, String catID) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("catid", catID));
        fireEvent(context, new CustomEventModel("category", params, new Date().getTime()));
    }

    public void subCategory(Context context, String subCat1ID) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("subcat1id", subCat1ID));
        fireEvent(context, new CustomEventModel(SUB_CATEGORY_EVENT, params, new Date().getTime()));
    }

    public void subSubCategory(Context context, String subCat2ID) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("subcat2id", subCat2ID));
        fireEvent(context, new CustomEventModel(SUB_SUB_CATEGORY_EVENT, params, new Date().getTime()));
    }

    public void productDetail(Context context, String pid) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("pid", pid));
        fireEvent(context, new CustomEventModel(PRODUCT_DETAIL_EVENT, params, new Date().getTime()));
    }

    public void shoppingCart(Context context, String pid1, int quantity1, String pid2, int quantity2, String pid3, int quantity3, Currency currency) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("pid1", pid1));
        params.add(new Pair("quantity1", new StringBuilder(String.valueOf(quantity1)).toString()));
        params.add(new Pair("pid2", pid2));
        params.add(new Pair("quantity2", new StringBuilder(String.valueOf(quantity2)).toString()));
        params.add(new Pair("pid3", pid3));
        params.add(new Pair("quantity3", new StringBuilder(String.valueOf(quantity3)).toString()));
        params.add(new Pair("currency", currency.getCode()));
        fireEvent(context, new CustomEventModel(SHOPPING_CART_EVENT, params, new Date().getTime()));
    }

    public void orderReview(Context context, String pid1, int quantity1, String pid2, int quantity2, String pid3, int quantity3, Currency currency) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("pid1", pid1));
        params.add(new Pair("quantity1", new StringBuilder(String.valueOf(quantity1)).toString()));
        params.add(new Pair("pid2", pid2));
        params.add(new Pair("quantity2", new StringBuilder(String.valueOf(quantity2)).toString()));
        params.add(new Pair("pid3", pid3));
        params.add(new Pair("quantity3", new StringBuilder(String.valueOf(quantity3)).toString()));
        params.add(new Pair("currency", currency.getCode()));
        fireEvent(context, new CustomEventModel(ORDER_REVIEW_EVENT, params, new Date().getTime()));
    }

    public void paymentModeSelection(Context context, String pid1, int quantity1, String pid2, int quantity2, String pid3, int quantity3, Currency currency) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("pid1", pid1));
        params.add(new Pair("quantity1", new StringBuilder(String.valueOf(quantity1)).toString()));
        params.add(new Pair("pid2", pid2));
        params.add(new Pair("quantity2", new StringBuilder(String.valueOf(quantity2)).toString()));
        params.add(new Pair("pid3", pid3));
        params.add(new Pair("quantity3", new StringBuilder(String.valueOf(quantity3)).toString()));
        params.add(new Pair("currency", currency.getCode()));
        fireEvent(context, new CustomEventModel(PAYMENT_MODE_EVENT, params, new Date().getTime()));
    }

    public void orderConfirmation(Context context, String orderID, long orderPrice, String pid1, String pid2, String pid3) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("orderid", orderID));
        params.add(new Pair("orderprice", new StringBuilder(String.valueOf(orderPrice)).toString()));
        params.add(new Pair("pid1", pid1));
        params.add(new Pair("pid2", pid2));
        params.add(new Pair("pid3", pid3));
        fireEvent(context, new CustomEventModel(ORDER_CONFIRMATION_EVENT, params, new Date().getTime()));
    }

    public void wishList(Context context, String pid1, int quantity1, String pid2, int quantity2, String pid3, int quantity3, Currency currency) {
        List<Pair<String, Object>> params = new ArrayList<>();
        params.add(new Pair("pid1", pid1));
        params.add(new Pair("quantity1", new StringBuilder(String.valueOf(quantity1)).toString()));
        params.add(new Pair("pid2", pid2));
        params.add(new Pair("quantity2", new StringBuilder(String.valueOf(quantity2)).toString()));
        params.add(new Pair("pid3", pid3));
        params.add(new Pair("quantity3", new StringBuilder(String.valueOf(quantity3)).toString()));
        params.add(new Pair("currency", currency.getCode()));
        fireEvent(context, new CustomEventModel(WISH_LIST_EVENT, params, new Date().getTime()));
    }

    public void onStartSession(final Context _context, final RequestParameter parameter, boolean sessionContinue) {
        Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
            public void run() {
                try {
                    if (CommonHelper.checkInternetConnection(_context)) {
                        try {
                            ArrayList<PurchaseItem> items = PurchaseRetryDAO.getDAO(_context).getRetryPurchase();
                            if (items != null && items.size() > 0) {
                                IgawLogger.Logging(_context, IgawConstant.QA_TAG, "Retry Purchase - count : " + items.size(), 2, true);
                                CommerceImpl.httpManager.purchaseForCommerce(parameter, _context, items);
                            }
                        } catch (Exception e) {
                            IgawLogger.Logging(_context, IgawConstant.QA_TAG, "Retry Purchase error : " + e.toString(), 0, false);
                        }
                        List<String> items2 = CommerceEventDAO.getEvents(_context);
                        if (items2 != null && items2.size() > 0) {
                            CommerceImpl.httpManager.customEventForCommerce(parameter, _context, items2, 0);
                        }
                        try {
                            ArrayList<CommerceV2EventItem> itemsForCommerceV2 = CommerceEventV2DAO.getDAO(_context).getEventForCommerceV2();
                            if (itemsForCommerceV2 != null && itemsForCommerceV2.size() > 0) {
                                IgawLogger.Logging(_context, IgawConstant.QA_TAG, "events for commerceV2 - count : " + itemsForCommerceV2.size(), 2, true);
                                CommerceImpl.httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(_context), _context, itemsForCommerceV2);
                            }
                        } catch (Exception e2) {
                            IgawLogger.Logging(_context, IgawConstant.QA_TAG, "events for commerceV2 error : " + e2.toString(), 0, false);
                        }
                    }
                } catch (Exception e3) {
                    IgawLogger.Logging(_context, IgawConstant.QA_TAG, e3.toString(), 0, false);
                }
            }
        });
    }

    public void onActivityCalled(Context context, String group, String activityName, RequestParameter parameter) {
    }

    public void onGetReferralResponse(Context context, String result) {
    }

    public void onEndSession(final Context context, final int sessionStackCount) {
        if (context == null) {
            Log.e(IgawConstant.QA_TAG, "Commerce >> onEndSession: null context.");
        } else {
            Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
                public void run() {
                    try {
                        if (CommonHelper.checkInternetConnection(context) && sessionStackCount == 0) {
                            List<String> items = CommerceEventDAO.getEvents(context);
                            if (items != null && items.size() > 0) {
                                CommerceImpl.httpManager.customEventForCommerce(RequestParameter.getATRequestParameter(context), context, items, 0);
                            }
                            try {
                                ArrayList<CommerceV2EventItem> itemsForCommerceV2 = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                                if (itemsForCommerceV2 != null && itemsForCommerceV2.size() > 0) {
                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "events for commerceV2 - count : " + itemsForCommerceV2.size(), 2, true);
                                    CommerceImpl.httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, itemsForCommerceV2);
                                }
                            } catch (Exception e) {
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "events for commerceV2 error : " + e.toString(), 0, false);
                            }
                        }
                    } catch (Exception e2) {
                        e2.printStackTrace();
                    }
                }
            });
        }
    }

    public void purchase(Context context, String productID, Double price, Currency currency, IgawPaymentMethod paymentMethod) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "purchase");
        IgawCommerceProductModel item = new IgawCommerceProductModel(productID, "", price, Double.valueOf(0.0d), Integer.valueOf(1), currency, null, null);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put("payment_method", paymentMethod.getMethod());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (context == null) {
            context = CommonFrameworkImpl.getContext();
        }
        if (context == null) {
            Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
        }
        try {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(item, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
        } catch (Exception e2) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry Purchaevent for CommerceV2se error : " + e2.toString(), 0, false);
        }
    }

    public void purchase(Context context, String orderID, IgawCommerceProductModel purchaseDetail, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "purchase");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderID);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
            jAttributes.put("payment_method", paymentMethod.getMethod());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (context == null) {
            context = CommonFrameworkImpl.getContext();
        }
        if (context == null) {
            Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
        }
        try {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(purchaseDetail, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
        } catch (Exception e2) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry Purchaevent for CommerceV2se error : " + e2.toString(), 0, false);
        }
    }

    public void purchaseBulk(Context context, String orderID, List<IgawCommerceProductModel> purchaseList, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "purchase");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderID);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
            jAttributes.put("payment_method", paymentMethod.getMethod());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!purchaseList.isEmpty()) {
            if (context == null) {
                context = CommonFrameworkImpl.getContext();
            }
            if (context == null) {
                Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
            }
            try {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(purchaseList, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            } catch (Exception e2) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry Purchaevent for CommerceV2se error : " + e2.toString(), 0, false);
            }
        }
    }

    public void appOpen(Context context) {
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, makeCommonJsonForCommerceV2(context, "app_open")).toString(), 0));
        if (CommonFrameworkImpl.isPremiumPostBack) {
            flushForCommerceV2(context);
        }
    }

    public void deeplinkOpen(Context context, String deeplinkUrl) {
        if (deeplinkUrl == null) {
            deeplinkUrl = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> deeplinkOpen for commerceV2 Param deeplink Url is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_DEEPLINK_OPEN);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put("deeplink_url", deeplinkUrl);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
    }

    public void login(Context context) {
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, makeCommonJsonForCommerceV2(context, "login")).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, makeCommonJsonForCommerceV2(context, "login")).toString(), 0));
    }

    public void refund(Context context, String orderId, IgawCommerceProductModel product, Double penaltyCharge) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> refund for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "refund");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("penalty_charge", penaltyCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (context == null) {
            context = CommonFrameworkImpl.getContext();
        }
        if (context == null) {
            Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
        }
        try {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "events for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
        } catch (Exception e2) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "refund for CommerceV2se error : " + e2.toString(), 0, false);
        }
    }

    public void refundBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double penaltyCharge) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> refund_bulk for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "refund");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("penalty_charge", penaltyCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!products.isEmpty()) {
            if (context == null) {
                context = CommonFrameworkImpl.getContext();
            }
            if (context == null) {
                Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
            }
            try {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "events for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            } catch (Exception e2) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "refund_bulk for CommerceV2se error : " + e2.toString(), 0, false);
            }
        }
    }

    public void addToCart(Context context, IgawCommerceProductModel product) {
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, makeCommonJsonForCommerceV2(context, "add_to_cart")).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, makeCommonJsonForCommerceV2(context, "add_to_cart")).toString(), 0));
    }

    public void addToCartBulk(Context context, List<IgawCommerceProductModel> products) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "add_to_cart");
        if (!products.isEmpty()) {
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
        }
    }

    public void addToWishList(Context context, IgawCommerceProductModel product) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "add_to_wishlist");
        makeProductJsonForCommerceV2(product, pObj);
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, pObj.toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, pObj.toString(), 0));
    }

    public void productView(Context context, IgawCommerceProductModel product) {
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, makeCommonJsonForCommerceV2(context, CV2_PRDUCT_VIEW)).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, makeCommonJsonForCommerceV2(context, CV2_PRDUCT_VIEW)).toString(), 0));
    }

    public void categoryView(Context context, IgawCommerceProductCategoryModel category) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_CATEGORY_VIEW);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            String[] categories = new String[5];
            String[] temp = category != null ? category.getCategoryFullString().split("\\.") : new String[0];
            for (int i = 0; i < temp.length; i++) {
                categories[i] = temp[i];
                jAttributes.put(String.format(Locale.US, "category%d", new Object[]{Integer.valueOf(i + 1)}), categories[i]);
            }
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public void categoryView(Context context, IgawCommerceProductCategoryModel category, List<IgawCommerceProductModel> products) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_CATEGORY_VIEW);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            String[] categories = new String[5];
            String[] temp = category != null ? category.getCategoryFullString().split("\\.") : new String[0];
            for (int i = 0; i < temp.length; i++) {
                categories[i] = temp[i];
                jAttributes.put(String.format(Locale.US, "category%d", new Object[]{Integer.valueOf(i + 1)}), categories[i]);
            }
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public void reviewOrder(Context context, String orderId, IgawCommerceProductModel product, Double discount, Double deliveryCharge) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> reviewOrder for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_REVIEW_ORDER);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
    }

    public void reviewOrderBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> reviewOrderBulk for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_REVIEW_ORDER);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!products.isEmpty()) {
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
        }
    }

    public void paymentView(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> paymentView for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_PAYMENT_VIEW);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!products.isEmpty()) {
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
        }
    }

    public void search(Context context, String keyword, List<IgawCommerceProductModel> resultProducts) {
        if (keyword == null) {
            keyword = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> search for commerceV2 Param keyword is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "search");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put("keyword", keyword);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!resultProducts.isEmpty()) {
            for (IgawCommerceProductModel item : resultProducts) {
                makeProductJsonForCommerceV2(item, pObj);
            }
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, pObj.toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, pObj.toString(), 0));
        }
    }

    public void share(Context context, IgawSharingChannel sharingChennel, IgawCommerceProductModel product) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "share");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            jAttributes.put("sharing_channel", sharingChennel);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
    }

    public JSONObject makeCommonJsonForCommerceV2(Context context, String pEventType) {
        JSONObject pObj = new JSONObject();
        new JSONObject();
        if (context == null) {
            context = CommonFrameworkImpl.getContext();
        }
        if (context == null) {
            Log.e(IgawConstant.QA_TAG, "makeCommonJsonForCommerceV2 >> Context is null. check start session is called.");
        }
        try {
            pObj.put("event_type", pEventType);
            pObj.put("event_id", UUID.randomUUID().toString());
            pObj.put("created_at", CommonHelper.GetKSTServerTimeAsString(context));
            JSONObject pObj_att = new JSONObject();
            try {
                pObj.put("attributes", pObj_att);
                JSONObject jSONObject = pObj_att;
            } catch (JSONException e) {
                e = e;
                JSONObject jSONObject2 = pObj_att;
                e.printStackTrace();
                return pObj;
            }
        } catch (JSONException e2) {
            e = e2;
            e.printStackTrace();
            return pObj;
        }
        return pObj;
    }

    public JSONObject makeProductJsonForCommerceV2(IgawCommerceProductModel product, JSONObject pObj) {
        JSONArray jArr_products;
        JSONObject jObj_product = new JSONObject();
        JSONObject product_attrs = new JSONObject();
        try {
            if (pObj.isNull("products")) {
                jArr_products = new JSONArray();
                pObj.put("products", jArr_products);
            } else {
                jArr_products = pObj.getJSONArray("products");
            }
            if (product == null) {
                return pObj;
            }
            jObj_product.put(CommerceDB.PRODUCT_ID, product.getProductID());
            jObj_product.put(CommerceDB.PRODUCT_NAME, product.getProductName());
            jObj_product.put("price", product.getPrice());
            jObj_product.put("discount", product.getDiscount());
            jObj_product.put("quantity", product.getQuantity());
            jObj_product.put("currency", product.getCurrency());
            String[] categories = new String[5];
            String[] temp = product.getCategory() != null ? product.getCategory().split("\\.") : new String[0];
            for (int i = 0; i < temp.length; i++) {
                categories[i] = temp[i];
                if (!temp[i].equals("")) {
                    product_attrs.put(String.format(Locale.US, "category%d", new Object[]{Integer.valueOf(i + 1)}), categories[i]);
                }
            }
            if (product.getExtraAttrs() != null) {
                for (String key : product.getExtraAttrs().keySet()) {
                    product_attrs.put(key, product.getExtraAttrs().get(key));
                }
            }
            jObj_product.put("extra_attrs", product_attrs);
            jArr_products.put(jObj_product);
            pObj.put("products", jArr_products);
            return pObj;
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
    }

    public JSONObject makeProductsJsonForCommerceV2(List<IgawCommerceProductModel> products, JSONObject pObj) {
        JSONArray jArr_products;
        try {
            if (pObj.isNull("products")) {
                jArr_products = new JSONArray();
                pObj.put("products", jArr_products);
            } else {
                jArr_products = pObj.getJSONArray("products");
            }
            if (products == null) {
                return pObj;
            }
            for (int i = 0; i < products.size(); i++) {
                if (products.get(i) != null) {
                    JSONObject jObj_product = new JSONObject();
                    IgawCommerceProductModel pItem = products.get(i);
                    jObj_product.put(CommerceDB.PRODUCT_ID, pItem.getProductID());
                    jObj_product.put(CommerceDB.PRODUCT_NAME, pItem.getProductName());
                    jObj_product.put("price", pItem.getPrice());
                    jObj_product.put("discount", pItem.getDiscount());
                    jObj_product.put("quantity", pItem.getQuantity());
                    jObj_product.put("currency", pItem.getCurrency());
                    JSONObject product_attrs = new JSONObject();
                    String[] categories = new String[5];
                    String[] temp = pItem.getCategory() != null ? pItem.getCategory().split("\\.") : new String[0];
                    for (int j = 0; j < temp.length; j++) {
                        categories[j] = temp[j];
                        if (!temp[j].equals("")) {
                            product_attrs.put(String.format(Locale.US, "category%d", new Object[]{Integer.valueOf(j + 1)}), categories[j]);
                        }
                    }
                    if (pItem.getExtraAttrs() != null) {
                        for (String key : pItem.getExtraAttrs().keySet()) {
                            product_attrs.put(key, pItem.getExtraAttrs().get(key));
                        }
                    }
                    jObj_product.put("extra_attrs", product_attrs);
                    jArr_products.put(jObj_product);
                    pObj.put("products", jArr_products);
                    if (i == 9) {
                        Log.w(IgawConstant.QA_TAG, "makeCommonJsonForCommerceV2 >> Products are too much. From the 11th product to the end product will be discarded!");
                        return pObj;
                    }
                }
            }
            return pObj;
        } catch (JSONException e) {
            e.printStackTrace();
            return null;
        }
    }

    private void restoreCV2EventInfo(Context context, CommerceV2EventItem item) {
        CommerceEventV2DAO dao = CommerceEventV2DAO.getDAO(context);
        ArrayList<CommerceV2EventItem> itemsForCommerceV2 = dao.getEventForCommerceV2();
        if (itemsForCommerceV2 != null && itemsForCommerceV2.size() >= 9) {
            try {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "events for commerceV2 - count : " + itemsForCommerceV2.size(), 2, true);
                itemsForCommerceV2.add(item);
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, itemsForCommerceV2);
            } catch (Exception e) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "events for commerceV2 error : " + e.toString(), 0, false);
            }
        } else if (item.getRetryCnt() > 5) {
            dao.removeRetryCount(item.getKey());
        } else {
            dao.updateOrInsertConversion(item.getKey(), item.getJson());
        }
    }

    public void flushForCommerceV2(final Context _context) {
        Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
            public void run() {
                try {
                    if (CommonHelper.checkInternetConnection(_context)) {
                        try {
                            ArrayList<CommerceV2EventItem> itemsForCommerceV2 = CommerceEventV2DAO.getDAO(_context).getEventForCommerceV2();
                            if (itemsForCommerceV2 != null && itemsForCommerceV2.size() > 0) {
                                IgawLogger.Logging(_context, IgawConstant.QA_TAG, "( premium flush )events for commerceV2 - count : " + itemsForCommerceV2.size(), 2, true);
                                CommerceImpl.httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(_context), _context, itemsForCommerceV2);
                            }
                        } catch (Exception e) {
                            IgawLogger.Logging(_context, IgawConstant.QA_TAG, "( premium flush )events for commerceV2 error : " + e.toString(), 0, false);
                        }
                    }
                } catch (Exception e2) {
                    IgawLogger.Logging(_context, IgawConstant.QA_TAG, e2.toString(), 0, false);
                }
            }
        });
    }

    public void purchase(Context context, String productID, Double price, Currency currency, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "purchase");
        IgawCommerceProductModel item = new IgawCommerceProductModel(productID, "", price, Double.valueOf(0.0d), Integer.valueOf(1), currency, null, null);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                TreeMap treeMap = new TreeMap(attrData);
                Iterator it = treeMap.keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = (String) it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    } else {
                        jAttributes.put(key, attrData.get(key));
                    }
                }
            }
            jAttributes.put("payment_method", paymentMethod.getMethod());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (context == null) {
            context = CommonFrameworkImpl.getContext();
        }
        if (context == null) {
            Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
        }
        try {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(item, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
        } catch (Exception e2) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry Purchaevent for CommerceV2se error : " + e2.toString(), 0, false);
        }
    }

    public void purchase(Context context, String orderID, IgawCommerceProductModel purchaseDetail, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "purchase");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderID);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
            jAttributes.put("payment_method", paymentMethod.getMethod());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (context == null) {
            context = CommonFrameworkImpl.getContext();
        }
        if (context == null) {
            Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
        }
        try {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(purchaseDetail, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
        } catch (Exception e2) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry Purchaevent for CommerceV2se error : " + e2.toString(), 0, false);
        }
    }

    public void purchaseBulk(Context context, String orderID, List<IgawCommerceProductModel> purchaseList, Double discount, Double deliveryCharge, IgawPaymentMethod paymentMethod, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "purchase");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderID);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
            jAttributes.put("payment_method", paymentMethod.getMethod());
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!purchaseList.isEmpty()) {
            if (context == null) {
                context = CommonFrameworkImpl.getContext();
            }
            if (context == null) {
                Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
            }
            try {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(purchaseList, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            } catch (Exception e2) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry Purchaevent for CommerceV2se error : " + e2.toString(), 0, false);
            }
        }
    }

    public void appOpen(Context context, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "app_open");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
        if (CommonFrameworkImpl.isPremiumPostBack) {
            flushForCommerceV2(context);
        }
    }

    public void deeplinkOpen(Context context, String deeplinkUrl, Map<String, String> attrData) {
        if (deeplinkUrl == null) {
            deeplinkUrl = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> deeplinkOpen for commerceV2 Param deeplink Url is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_DEEPLINK_OPEN);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put("deeplink_url", deeplinkUrl);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
    }

    public void login(Context context, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "login");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
    }

    public void refund(Context context, String orderId, IgawCommerceProductModel product, Double penaltyCharge, Map<String, String> attrData) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> refund for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "refund");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("penalty_charge", penaltyCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (context == null) {
            context = CommonFrameworkImpl.getContext();
        }
        if (context == null) {
            Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
        }
        try {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "events for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
        } catch (Exception e2) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "refund for CommerceV2se error : " + e2.toString(), 0, false);
        }
    }

    public void refundBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double penaltyCharge, Map<String, String> attrData) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> refund_bulk for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "refund");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("penalty_charge", penaltyCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!products.isEmpty()) {
            if (context == null) {
                context = CommonFrameworkImpl.getContext();
            }
            if (context == null) {
                Log.e(IgawConstant.QA_TAG, "purchase CommerceV2 >> Context is null. check start session is called.");
            }
            try {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "events for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            } catch (Exception e2) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "refund_bulk for CommerceV2se error : " + e2.toString(), 0, false);
            }
        }
    }

    public void addToCart(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "add_to_cart");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
    }

    public void addToCartBulk(Context context, List<IgawCommerceProductModel> products, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "add_to_cart");
        if (!products.isEmpty()) {
            try {
                JSONObject jAttributes = pObj.getJSONObject("attributes");
                if (jAttributes == null) {
                    jAttributes = new JSONObject();
                    pObj.put("attributes", jAttributes);
                }
                if (attrData != null) {
                    int attrCount = 0;
                    Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                    while (true) {
                        if (!it.hasNext()) {
                            break;
                        }
                        String key = it.next();
                        attrCount++;
                        if (attrCount > 5) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                            break;
                        }
                        jAttributes.put(key, attrData.get(key));
                    }
                }
            } catch (JSONException e) {
                e.printStackTrace();
            }
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
        }
    }

    public void addToWishList(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "add_to_wishlist");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
    }

    public void productView(Context context, IgawCommerceProductModel product, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_PRDUCT_VIEW);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
    }

    public void categoryView(Context context, IgawCommerceProductCategoryModel category, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_CATEGORY_VIEW);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                TreeMap treeMap = new TreeMap(attrData);
                Iterator it = treeMap.keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = (String) it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            String[] categories = new String[5];
            String[] temp = category != null ? category.getCategoryFullString().split("\\.") : new String[0];
            for (int i = 0; i < temp.length; i++) {
                categories[i] = temp[i];
                jAttributes.put(String.format(Locale.US, "category%d", new Object[]{Integer.valueOf(i + 1)}), categories[i]);
            }
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(null, pObj).toString(), 0));
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public void categoryView(Context context, IgawCommerceProductCategoryModel category, List<IgawCommerceProductModel> products, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_CATEGORY_VIEW);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                TreeMap treeMap = new TreeMap(attrData);
                Iterator it = treeMap.keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = (String) it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            String[] categories = new String[5];
            String[] temp = category != null ? category.getCategoryFullString().split("\\.") : new String[0];
            for (int i = 0; i < temp.length; i++) {
                categories[i] = temp[i];
                jAttributes.put(String.format(Locale.US, "category%d", new Object[]{Integer.valueOf(i + 1)}), categories[i]);
            }
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
        } catch (JSONException e) {
            e.printStackTrace();
        }
    }

    public void reviewOrder(Context context, String orderId, IgawCommerceProductModel product, Double discount, Double deliveryCharge, Map<String, String> attrData) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> reviewOrder for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_REVIEW_ORDER);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
    }

    public void reviewOrderBulk(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge, Map<String, String> attrData) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> reviewOrderBulk for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_REVIEW_ORDER);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!products.isEmpty()) {
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
        }
    }

    public void paymentView(Context context, String orderId, List<IgawCommerceProductModel> products, Double discount, Double deliveryCharge, Map<String, String> attrData) {
        if (orderId == null) {
            orderId = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> paymentView for commerceV2 Param orderId is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, CV2_PAYMENT_VIEW);
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put(CommerceDB.ORDER_ID, orderId);
            jAttributes.put("discount", discount);
            jAttributes.put("delivery_charge", deliveryCharge);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!products.isEmpty()) {
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductsJsonForCommerceV2(products, pObj).toString(), 0));
        }
    }

    public void search(Context context, String keyword, List<IgawCommerceProductModel> resultProducts, Map<String, String> attrData) {
        if (keyword == null) {
            keyword = "";
            Log.i(IgawConstant.QA_TAG, "Commerce >> search for commerceV2 Param keyword is 'null'");
        }
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "search");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put("keyword", keyword);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (!resultProducts.isEmpty()) {
            for (IgawCommerceProductModel item : resultProducts) {
                makeProductJsonForCommerceV2(item, pObj);
            }
            if (CommonFrameworkImpl.isPremiumPostBack) {
                ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
                if (items != null && items.size() > 0) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
                }
                items.add(new CommerceV2EventItem(-1, pObj.toString(), 0));
                httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
                return;
            }
            restoreCV2EventInfo(context, new CommerceV2EventItem(-1, pObj.toString(), 0));
        }
    }

    public void share(Context context, IgawSharingChannel sharingChennel, IgawCommerceProductModel product, Map<String, String> attrData) {
        JSONObject pObj = makeCommonJsonForCommerceV2(context, "share");
        try {
            JSONObject jAttributes = pObj.getJSONObject("attributes");
            if (jAttributes == null) {
                jAttributes = new JSONObject();
                pObj.put("attributes", jAttributes);
            }
            if (attrData != null) {
                int attrCount = 0;
                Iterator<String> it = new TreeMap<>(attrData).keySet().iterator();
                while (true) {
                    if (!it.hasNext()) {
                        break;
                    }
                    String key = it.next();
                    attrCount++;
                    if (attrCount > 5) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "IgawCommerceEventAttr parmater counts must set less then 5, data from the 6th to the end gonna be missed!!", 1, true);
                        break;
                    }
                    jAttributes.put(key, attrData.get(key));
                }
            }
            jAttributes.put("sharing_channel", sharingChennel);
        } catch (JSONException e) {
            e.printStackTrace();
        }
        if (CommonFrameworkImpl.isPremiumPostBack) {
            ArrayList<CommerceV2EventItem> items = CommerceEventV2DAO.getDAO(context).getEventForCommerceV2();
            if (items != null && items.size() > 0) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Retry event for CommerceV2 - count : " + items.size(), 2, true);
            }
            items.add(new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
            httpManager.eventForCommerceV2(RequestParameter.getATRequestParameter(context), context, items);
            return;
        }
        restoreCV2EventInfo(context, new CommerceV2EventItem(-1, makeProductJsonForCommerceV2(product, pObj).toString(), 0));
    }
}