package com.nuvent.shareat.activity.main;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.res.Resources;
import android.graphics.Color;
import android.graphics.Rect;
import android.os.AsyncTask;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.annotation.Nullable;
import android.support.design.widget.TabLayout;
import android.support.design.widget.TabLayout.OnTabSelectedListener;
import android.support.design.widget.TabLayout.Tab;
import android.support.design.widget.TabLayout.TabLayoutOnPageChangeListener;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.support.v7.widget.AppCompatSpinner;
import android.text.Html;
import android.view.KeyCharacterMap;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.view.animation.AnimationUtils;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.FrameLayout.LayoutParams;
import android.widget.ImageView;
import android.widget.SpinnerAdapter;
import android.widget.TextView;
import android.widget.Toast;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.DeliveryObjectInfoApi;
import com.nuvent.shareat.api.DeliveryPossibleAreaApi;
import com.nuvent.shareat.api.DeliveryShippingAddressApi;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.event.CardSlideEvent;
import com.nuvent.shareat.event.CardUpdateEvent;
import com.nuvent.shareat.event.CardViewStatusEvent;
import com.nuvent.shareat.event.DeliveryActivityFinishEvent;
import com.nuvent.shareat.event.GuideCloseEvent;
import com.nuvent.shareat.fragment.DeliveryDefaultAddressFragment;
import com.nuvent.shareat.fragment.DeliveryDirectlyAddressFragment;
import com.nuvent.shareat.fragment.DeliveryDirectlyAddressFragment.FOCUS_OBJECT;
import com.nuvent.shareat.fragment.DeliveryRecentAddressFragment;
import com.nuvent.shareat.manager.sns.BaseSnsManager;
import com.nuvent.shareat.model.delivery.DeliveryObjectInfoResultModel;
import com.nuvent.shareat.model.delivery.DeliveryPossibleAreaDetailModel;
import com.nuvent.shareat.model.delivery.DeliveryPossibleAreaModel;
import com.nuvent.shareat.model.delivery.DeliveryPossibleDateModel;
import com.nuvent.shareat.model.delivery.DeliveryShippingAddressDefaultModel;
import com.nuvent.shareat.model.delivery.DeliveryShippingAddressRecentModel;
import com.nuvent.shareat.model.delivery.DeliveryShippingAddressResultModel;
import com.nuvent.shareat.model.payment.PaymentDetailModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.AndroidBug5497Workaround;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.view.CardView;
import de.greenrobot.event.EventBus;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import net.xenix.android.widget.CustomViewPager;
import net.xenix.android.widget.FontEditTextView;
import net.xenix.util.FormatUtil;
import net.xenix.util.ImageDisplay;

public class DeliveryActivity extends MainActionBarActivity {
    /* access modifiers changed from: private */
    public CustomViewPager customViewPager;
    /* access modifiers changed from: private */
    public DeliveryObjectInfoResultModel deliveryObjectInfoResultModel;
    /* access modifiers changed from: private */
    public ArrayList<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> deliveryPossibleAreaModels;
    /* access modifiers changed from: private */
    public DeliveryShippingAddressDefaultModel deliveryShippingAddressDefaultModel;
    /* access modifiers changed from: private */
    public ArrayList<DeliveryShippingAddressRecentModel> deliveryShippingAddressRecentModels;
    private LayoutParams frameLayoutParams;
    private OnGlobalLayoutListener layoutListener;
    private View mChildOfContent;
    private int softKeyHeight = 0;
    /* access modifiers changed from: private */
    public StoreModel storeModel;
    private TabLayout tabLayout;
    /* access modifiers changed from: private */
    public String thirdPartyLawContent;
    private int usableHeightPrevious;

    public class ShippingAddressPager extends FragmentStatePagerAdapter {
        DeliveryDefaultAddressFragment fragment1;
        DeliveryRecentAddressFragment fragment2;
        DeliveryDirectlyAddressFragment fragment3;
        private int tabCount;

        public ShippingAddressPager(FragmentManager fm, int tabCount2) {
            super(fm);
            this.tabCount = tabCount2;
        }

        public Fragment getItem(int position) {
            switch (position) {
                case 0:
                    if (this.fragment1 == null) {
                        this.fragment1 = new DeliveryDefaultAddressFragment(DeliveryActivity.this.deliveryShippingAddressDefaultModel, DeliveryActivity.this.deliveryObjectInfoResultModel.getMethod());
                    }
                    return this.fragment1;
                case 1:
                    if (this.fragment2 == null) {
                        this.fragment2 = new DeliveryRecentAddressFragment(DeliveryActivity.this.deliveryShippingAddressRecentModels);
                    }
                    return this.fragment2;
                case 2:
                    if (this.fragment3 == null) {
                        this.fragment3 = new DeliveryDirectlyAddressFragment(DeliveryActivity.this.deliveryObjectInfoResultModel.getMethod());
                    }
                    return this.fragment3;
                default:
                    return null;
            }
        }

        public int getCount() {
            return this.tabCount;
        }
    }

    class ThirdPartyLawTask extends AsyncTask<Integer, Integer, Integer> {
        ThirdPartyLawTask() {
        }

        /* access modifiers changed from: protected */
        public void onPreExecute() {
        }

        /* access modifiers changed from: protected */
        public Integer doInBackground(Integer... arg0) {
            DeliveryActivity.this.thirdPartyLawContent = DeliveryActivity.this.requestThirdPartyContent(DeliveryActivity.this.getResources().getString(R.string.delivery_third_party_law_link));
            return null;
        }

        /* access modifiers changed from: protected */
        public void onPostExecute(Integer a) {
            ((TextView) DeliveryActivity.this.findViewById(R.id.third_party_law_content)).setText(Html.fromHtml(DeliveryActivity.this.thirdPartyLawContent));
        }
    }

    /* access modifiers changed from: protected */
    public void onResume() {
        super.onResume();
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        GAEvent.onGAScreenView(this, R.string.ga_delivery_view);
        EventBus.getDefault().register(this);
        setContentView(R.layout.activity_delivery, 2);
        showFavoriteButton(false);
        setTitle("\uc8fc\ubb38/\uacb0\uc81c");
        this.storeModel = (StoreModel) getIntent().getSerializableExtra("store_model");
        requestObjectInfo();
        setCardInfo();
        bidingClickEvent();
        new ThirdPartyLawTask().execute(new Integer[0]);
        AndroidBug5497Workaround.assistActivity(this, R.id.delivery_scroll_view);
        getWindow().setSoftInputMode(19);
    }

    private int getSoftMenuHeight(Activity activity) {
        Resources resources = activity.getResources();
        int resourceId = resources.getIdentifier("navigation_bar_height", "dimen", "android");
        if (resourceId > 0) {
            return resources.getDimensionPixelSize(resourceId);
        }
        return 0;
    }

    private boolean isIncludeSoftKey(Activity activity) {
        boolean bHasMenuKey = ViewConfiguration.get(activity).hasPermanentMenuKey();
        boolean bHasBackKey = KeyCharacterMap.deviceHasKey(4);
        if (bHasMenuKey || bHasBackKey) {
            return false;
        }
        return true;
    }

    private void possiblyResizeChildOfContent(Activity activity) {
        int usableHeightNow = computeUsableHeight(activity);
        if (usableHeightNow != this.usableHeightPrevious) {
            int usableHeightSansKeyboard = this.mChildOfContent.getRootView().getHeight() - this.softKeyHeight;
            if (VERSION.SDK_INT < 19) {
                Rect frame = new Rect();
                activity.getWindow().getDecorView().getWindowVisibleDisplayFrame(frame);
                usableHeightSansKeyboard -= frame.top;
            }
            int heightDifference = usableHeightSansKeyboard - usableHeightNow;
            if (heightDifference > usableHeightSansKeyboard / 4) {
                this.frameLayoutParams.height = usableHeightSansKeyboard - heightDifference;
            } else {
                this.frameLayoutParams.height = usableHeightSansKeyboard;
            }
            this.mChildOfContent.requestLayout();
            this.usableHeightPrevious = usableHeightNow;
        }
    }

    private int computeUsableHeight(Activity activity) {
        if (activity.getCurrentFocus() instanceof EditText) {
            return 0;
        }
        Rect frame = new Rect();
        activity.getWindow().getDecorView().getWindowVisibleDisplayFrame(frame);
        int statusBarHeight = frame.top;
        Rect r = new Rect();
        this.mChildOfContent.getWindowVisibleDisplayFrame(r);
        if (VERSION.SDK_INT >= 19) {
            return (r.bottom - r.top) + statusBarHeight;
        }
        return r.bottom - r.top;
    }

    public void onClickCloseCard(View view) {
        super.onClickCloseCard(view);
        animateCardLayout(false);
    }

    /* access modifiers changed from: private */
    public void setTab() {
        this.tabLayout = (TabLayout) findViewById(R.id.tab_layout);
        if (true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(this.storeModel.getMethod())) {
            this.tabLayout.addTab(this.tabLayout.newTab().setText((int) R.string.delivery_address_tab4));
            this.tabLayout.addTab(this.tabLayout.newTab().setText((int) R.string.delivery_address_tab5));
        } else {
            this.tabLayout.addTab(this.tabLayout.newTab().setText((int) R.string.delivery_address_tab1));
            this.tabLayout.addTab(this.tabLayout.newTab().setText((int) R.string.delivery_address_tab2));
        }
        this.tabLayout.addTab(this.tabLayout.newTab().setText((int) R.string.delivery_address_tab3));
        this.tabLayout.setTabGravity(0);
        this.tabLayout.setSelectedTabIndicatorHeight(1);
        this.tabLayout.setSelectedTabIndicatorColor(Color.parseColor("#6385e6"));
        this.tabLayout.setTabTextColors(Color.parseColor("#7e8495"), Color.parseColor("#6385e6"));
        this.tabLayout.setOnTabSelectedListener(new OnTabSelectedListener() {
            public void onTabSelected(Tab tab) {
                if (tab.getPosition() != DeliveryActivity.this.customViewPager.getCurrentItem()) {
                    DeliveryActivity.this.customViewPager.setCurrentItem(tab.getPosition());
                }
            }

            public void onTabUnselected(Tab tab) {
            }

            public void onTabReselected(Tab tab) {
                if (tab.getPosition() != DeliveryActivity.this.customViewPager.getCurrentItem()) {
                    DeliveryActivity.this.customViewPager.setCurrentItem(tab.getPosition());
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public void setViewPager() {
        this.customViewPager = (CustomViewPager) findViewById(R.id.shipping_address_pager);
        this.customViewPager.setAdapter(new ShippingAddressPager(getSupportFragmentManager(), this.tabLayout.getTabCount()));
        this.customViewPager.setAddStatesFromChildren(false);
        this.customViewPager.setCurrentItem(0);
        this.customViewPager.setOffscreenPageLimit(this.tabLayout.getTabCount());
        this.customViewPager.measure(-1, -2);
        this.customViewPager.addOnPageChangeListener(new TabLayoutOnPageChangeListener(this.tabLayout));
        this.customViewPager.addOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
    }

    public void onBackPressed() {
        if (!((CardView) findViewById(R.id.cardView)).isPayingMode()) {
            if (true == isOpenCardView()) {
                animateCardLayout(false);
                closeCardView();
                return;
            }
            finish();
        }
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        EventBus.getDefault().unregister(this);
        super.onDestroy();
    }

    /* access modifiers changed from: protected */
    public void onPause() {
        super.onPause();
    }

    private void requestObjectInfo() {
        DeliveryObjectInfoApi request = new DeliveryObjectInfoApi(this);
        request.addGetParam(String.format("?partner_sno=%s&phone_os=A", new Object[]{this.storeModel.getPartnerSno()}));
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                DeliveryActivity.this.deliveryObjectInfoResultModel = (DeliveryObjectInfoResultModel) result;
                DeliveryActivity.this.setMobileNumInfo();
                DeliveryActivity.this.setObjectInfo(DeliveryActivity.this.deliveryObjectInfoResultModel);
                DeliveryActivity.this.requestShippingAddressInfo();
            }

            public void onFailure(Exception exception) {
                super.onFailure(exception);
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestShippingAddressInfo() {
        new DeliveryShippingAddressApi(this).request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                DeliveryShippingAddressResultModel model = (DeliveryShippingAddressResultModel) result;
                DeliveryActivity.this.deliveryShippingAddressRecentModels = model.getOrder_address_list();
                DeliveryActivity.this.deliveryShippingAddressDefaultModel = model.getDefault_address();
                DeliveryActivity.this.setTab();
                DeliveryActivity.this.setViewPager();
                DeliveryActivity.this.setActiveAddressPage();
                DeliveryActivity.this.requestDeliveryPossibleArea();
            }

            public void onFailure(Exception exception) {
                super.onFailure(exception);
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }

    private void bidingClickEvent() {
        findViewById(R.id.order_agreement_content_status).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                boolean isVisible;
                if (DeliveryActivity.this.findViewById(R.id.order_agreement_content_layout).getVisibility() == 0) {
                    isVisible = true;
                } else {
                    isVisible = false;
                }
                if (true == isVisible) {
                    GAEvent.onGaEvent((Activity) DeliveryActivity.this, (int) R.string.ga_delivery_view, (int) R.string.ga_ev_click, (int) R.string.ga_delivery_agreement_show);
                    DeliveryActivity.this.findViewById(R.id.order_agreement_content_layout).setVisibility(8);
                    ((TextView) DeliveryActivity.this.findViewById(R.id.order_agreement_content_status)).setText("\ub0b4\uc6a9\ubcf4\uae30");
                    return;
                }
                GAEvent.onGaEvent((Activity) DeliveryActivity.this, (int) R.string.ga_delivery_view, (int) R.string.ga_ev_click, (int) R.string.ga_delivery_agreement_hide);
                DeliveryActivity.this.findViewById(R.id.order_agreement_content_layout).setVisibility(0);
                ((TextView) DeliveryActivity.this.findViewById(R.id.order_agreement_content_status)).setText("\ub0b4\uc6a9\ub2eb\uae30");
            }
        });
        findViewById(R.id.delivery_payment).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                Map<String, String> data;
                if (DeliveryActivity.this.validationCheck()) {
                    ((CardView) DeliveryActivity.this.findViewById(R.id.cardView)).setStoreModel(DeliveryActivity.this.storeModel);
                    HashMap hashMap = new HashMap();
                    Fragment fragment = ((ShippingAddressPager) DeliveryActivity.this.customViewPager.getAdapter()).getItem(DeliveryActivity.this.customViewPager.getCurrentItem());
                    if (fragment instanceof DeliveryDefaultAddressFragment) {
                        data = ((DeliveryDefaultAddressFragment) fragment).getReceiverInfo();
                    } else if (fragment instanceof DeliveryRecentAddressFragment) {
                        data = ((DeliveryRecentAddressFragment) fragment).getReceiverInfo();
                    } else {
                        data = ((DeliveryDirectlyAddressFragment) fragment).getReceiverInfo();
                        hashMap.put("defaultAddressYN", data.get("defaultAddress").toString());
                        hashMap.put("useSafePhone", data.get("useSafePhone").toString());
                    }
                    hashMap.put("receiveName", data.get("receiveName").toString());
                    hashMap.put("address", data.get("address").toString());
                    hashMap.put("addressRest", data.get("addressRest").toString());
                    hashMap.put("receivePhone", data.get("receivePhone").toString());
                    hashMap.put("zipCode", data.get("zipCode").toString());
                    hashMap.put("requestMessage", data.get("requestMessage").toString());
                    TextView orderObjectName = (TextView) DeliveryActivity.this.findViewById(R.id.order_object_name);
                    TextView orderName = (TextView) DeliveryActivity.this.findViewById(R.id.order_name);
                    TextView orderPhoneNum = (TextView) DeliveryActivity.this.findViewById(R.id.order_phone_number);
                    TextView textView = (TextView) DeliveryActivity.this.findViewById(R.id.receiver_inquire);
                    AppCompatSpinner appCompatSpinner = (AppCompatSpinner) DeliveryActivity.this.findViewById(R.id.order_possible_date);
                    hashMap.put("orderName", orderName.getText().toString());
                    hashMap.put("orderPhone", ((String) ((AppCompatSpinner) DeliveryActivity.this.findViewById(R.id.mobile_num)).getSelectedItem()) + orderPhoneNum.getText().toString());
                    hashMap.put("deliverPrice", AppEventsConstants.EVENT_PARAM_VALUE_NO);
                    String orderCountText = ((AppCompatSpinner) DeliveryActivity.this.findViewById(R.id.order_count)).getSelectedItem().toString();
                    String orderCountText2 = orderCountText.substring("\uc218\ub7c9 : ".length(), orderCountText.length());
                    String orderCountText3 = orderCountText2.substring(0, orderCountText2.indexOf("\uac1c"));
                    hashMap.put("count", orderCountText3);
                    hashMap.put("itemPrice", DeliveryActivity.this.deliveryObjectInfoResultModel.getMenuPrice());
                    hashMap.put("dateSno", ((TextView) DeliveryActivity.this.findViewById(R.id.possible_date_sno)).getText().toString());
                    hashMap.put("payKind", "CARD");
                    hashMap.put("pwdGubun", AppEventsConstants.EVENT_PARAM_VALUE_NO);
                    hashMap.put("menuImagePath", DeliveryActivity.this.deliveryObjectInfoResultModel.getMenuImagePath());
                    String zipCode = (String) hashMap.get("zipCode");
                    if (!zipCode.isEmpty()) {
                        zipCode = "(" + zipCode + ")";
                    }
                    String fullAddress = zipCode + ((String) hashMap.get("address")) + " " + ((String) hashMap.get("addressRest"));
                    int totalPayAmt = Integer.valueOf(orderCountText3).intValue() * Integer.valueOf(DeliveryActivity.this.deliveryObjectInfoResultModel.getMenuPrice()).intValue();
                    String orderPossibleDate = ((AppCompatSpinner) DeliveryActivity.this.findViewById(R.id.order_possible_date)).getSelectedItem().toString();
                    String orderPossibleDate2 = orderPossibleDate.substring(0, orderPossibleDate.indexOf(" - "));
                    DeliveryActivity deliveryActivity = DeliveryActivity.this;
                    DeliveryActivity deliveryActivity2 = DeliveryActivity.this;
                    Object[] objArr = new Object[13];
                    objArr[0] = orderObjectName.getText().toString();
                    objArr[1] = String.valueOf(orderCountText3);
                    objArr[2] = FormatUtil.onDecimalFormat(String.valueOf((Integer.valueOf(orderCountText3).intValue() * Integer.valueOf(DeliveryActivity.this.deliveryObjectInfoResultModel.getMenuOriginPrice()).intValue()) - totalPayAmt)) + "\uc6d0";
                    objArr[3] = FormatUtil.onDecimalFormat(String.valueOf(totalPayAmt)) + "\uc6d0";
                    objArr[4] = orderName.getText().toString();
                    objArr[5] = ((AppCompatSpinner) DeliveryActivity.this.findViewById(R.id.mobile_num)).getSelectedItem().toString() + orderPhoneNum.getText().toString();
                    objArr[6] = hashMap.get("receiveName");
                    objArr[7] = true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(DeliveryActivity.this.storeModel.getMethod()) ? "\ubc30\ub2ec" : "\ubc30\uc1a1";
                    objArr[8] = orderPossibleDate2;
                    objArr[9] = fullAddress;
                    objArr[10] = hashMap.get("receivePhone");
                    objArr[11] = true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(DeliveryActivity.this.storeModel.getMethod()) ? "\ubc30\ub2ec" : "\ubc30\uc1a1";
                    objArr[12] = hashMap.get("requestMessage");
                    final HashMap hashMap2 = hashMap;
                    deliveryActivity.showCustomConfirmDialog("[\uc8fc\ubb38/\uacb0\uc81c \ud655\uc778]", deliveryActivity2.getString(R.string.payment_confirm_alert_message, objArr), "\ucde8\uc18c", "\ud655\uc778", new Runnable() {
                        public void run() {
                        }
                    }, new Runnable() {
                        public void run() {
                            GAEvent.onGaEvent((Activity) DeliveryActivity.this, (int) R.string.ga_delivery_view, (int) R.string.ga_ev_click, (int) R.string.ga_delivery_info_confirm);
                            DeliveryActivity.this.hideKeyboard();
                            ((CardView) DeliveryActivity.this.findViewById(R.id.cardView)).setDeliveryInfoData(hashMap2);
                            DeliveryActivity.this.animateCardLayout(true);
                            DeliveryActivity.this.openCardView();
                        }
                    });
                }
            }
        });
    }

    /* access modifiers changed from: private */
    public boolean validationCheck() {
        final FontEditTextView orderName = (FontEditTextView) findViewById(R.id.order_name);
        if (true == orderName.getText().toString().isEmpty()) {
            orderName.clearFocus();
            AnonymousClass7 r0 = new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    orderName.requestFocus();
                }
            };
            showDialog("\uc8fc\ubb38\uc790 \uc815\ubcf4(\uc774\ub984) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", r0);
            return false;
        }
        FontEditTextView orderPhoneNumber = (FontEditTextView) findViewById(R.id.order_phone_number);
        if (true == orderPhoneNumber.getText().toString().isEmpty()) {
            orderPhoneNumber.clearFocus();
            final FontEditTextView fontEditTextView = orderPhoneNumber;
            AnonymousClass8 r02 = new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    fontEditTextView.requestFocus();
                }
            };
            showDialog("\uc8fc\ubb38\uc790 \uc815\ubcf4(\uc804\ud654\ubc88\ud638) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", r02);
            return false;
        }
        Fragment fragment = ((ShippingAddressPager) this.customViewPager.getAdapter()).getItem(this.customViewPager.getCurrentItem());
        if (fragment instanceof DeliveryDefaultAddressFragment) {
            ((DeliveryDefaultAddressFragment) fragment).getReceiverInfo();
        } else if (fragment instanceof DeliveryRecentAddressFragment) {
            ((DeliveryRecentAddressFragment) fragment).getReceiverInfo();
        } else {
            final DeliveryDirectlyAddressFragment deliveryDirectlyAddressFragment = (DeliveryDirectlyAddressFragment) fragment;
            Map<String, String> data = deliveryDirectlyAddressFragment.getReceiverInfo();
            String receiverName = data.get("receiveName").toString();
            String str = data.get("address").toString();
            String addressRest = data.get("addressRest").toString();
            String receivePhone = data.get("receivePhone").toString();
            String zipCode = data.get("zipCode").toString();
            String str2 = data.get("defaultAddress").toString();
            String str3 = data.get("useSafePhone").toString();
            if (true == this.deliveryObjectInfoResultModel.getMethod().equals(HttpRequest.METHOD_POST) && true == zipCode.isEmpty()) {
                AnonymousClass9 r03 = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        deliveryDirectlyAddressFragment.moveFocus(FOCUS_OBJECT.ZIP_CODE);
                    }
                };
                showDialog("\ubc30\uc1a1\uc9c0 \uc815\ubcf4(\uc6b0\ud3b8\ubc88\ud638) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", r03);
                return false;
            } else if (true == receiverName.isEmpty()) {
                AnonymousClass10 r04 = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        deliveryDirectlyAddressFragment.moveFocus(FOCUS_OBJECT.RECEIVER_NAME);
                    }
                };
                showDialog("\ubc30\uc1a1\uc9c0 \uc815\ubcf4(\uc774\ub984) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", r04);
                return false;
            } else if (true == addressRest.isEmpty()) {
                AnonymousClass11 r05 = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        deliveryDirectlyAddressFragment.moveFocus(FOCUS_OBJECT.ADDRESS_REST);
                    }
                };
                showDialog("\ubc30\uc1a1\uc9c0 \uc815\ubcf4(\uc0c1\uc138\uc8fc\uc18c) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", r05);
                return false;
            } else if (true == receivePhone.isEmpty()) {
                AnonymousClass12 r06 = new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        deliveryDirectlyAddressFragment.moveFocus(FOCUS_OBJECT.RECEIVER_PHONE);
                    }
                };
                showDialog("\ubc30\uc1a1\uc9c0 \uc815\ubcf4(\uc804\ud654\ubc88\ud638) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", r06);
                return false;
            }
        }
        final AppCompatSpinner orderCountSpinner = (AppCompatSpinner) findViewById(R.id.order_count);
        String orderCountText = orderCountSpinner.getSelectedItem().toString();
        String orderCountText2 = orderCountText.substring("\uc218\ub7c9 : ".length(), orderCountText.length());
        if (Integer.parseInt(orderCountText2.substring(0, orderCountText2.indexOf("\uac1c"))) == 0) {
            orderCountSpinner.clearFocus();
            AnonymousClass13 r07 = new DialogInterface.OnClickListener() {
                public void onClick(DialogInterface dialog, int which) {
                    DeliveryActivity.this.hideKeyboard();
                    orderCountSpinner.requestFocus();
                }
            };
            showDialog("\ud574\ub2f9\uc77c \uc778\ub2f9 \uc8fc\ubb38 \uac00\ub2a5 \uc218\ub7c9\uc774 \ucd08\uacfc\ub418\uc5c8\uc2b5\ub2c8\ub2e4 .", r07);
            return false;
        }
        CheckBox thirdPartyLawAgreement = (CheckBox) findViewById(R.id.third_party_law_agreement);
        if (thirdPartyLawAgreement.isChecked()) {
            return true;
        }
        thirdPartyLawAgreement.clearFocus();
        final CheckBox checkBox = thirdPartyLawAgreement;
        AnonymousClass14 r08 = new DialogInterface.OnClickListener() {
            public void onClick(DialogInterface dialog, int which) {
                checkBox.requestFocus();
            }
        };
        showDialog("\uac1c\uc778\uc815\ubcf4 \uc81c3\uc790 \uc815\ubcf4\uc81c\uacf5 \ub3d9\uc758\ub97c \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694.", r08);
        return false;
    }

    /* access modifiers changed from: private */
    public void setMobileNumInfo() {
        AppCompatSpinner mobileNumSpinner = (AppCompatSpinner) findViewById(R.id.mobile_num);
        ArrayList<String> mobileNums = new ArrayList<>();
        mobileNums.add("010");
        mobileNums.add("011");
        mobileNums.add("017");
        mobileNums.add("018");
        mobileNums.add("070");
        mobileNums.add(BaseSnsManager.SNS_LOGIN_TYPE_KAKAO);
        mobileNums.add("031");
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, R.layout.spinner_textview, mobileNums);
        mobileNumSpinner.setAdapter((SpinnerAdapter) adapter);
        adapter.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
        mobileNumSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
    }

    /* access modifiers changed from: private */
    public void setObjectInfo(DeliveryObjectInfoResultModel model) {
        final ArrayList<DeliveryPossibleDateModel> possibleDates = model.getResult_list();
        ImageView objectImage = (ImageView) findViewById(R.id.object_image);
        TextView orderObjectName = (TextView) findViewById(R.id.order_object_name);
        TextView textView = (TextView) findViewById(R.id.object_max_count);
        TextView deliveryComment = (TextView) findViewById(R.id.delivery_comment);
        TextView freeDelivery = (TextView) findViewById(R.id.order_object_no_charge);
        TextView possibleSectionTitle = (TextView) findViewById(R.id.possible_section_title);
        TextView shippingSectionTitle = (TextView) findViewById(R.id.shipping_section_title);
        if (true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(this.storeModel.getMethod())) {
            freeDelivery.setText("\ubc30\ub2ec\uc0c1\ud488");
            deliveryComment.setText("\ubc30\ub2ec\uc77c 17\uc2dc\uacbd \uc77c\uad04 \ucd9c\ubc1c\ud558\uba70, 1~2\uc2dc\uac04 \uc18c\uc694\uac00 \uc608\uc0c1\ub429\ub2c8\ub2e4.");
            possibleSectionTitle.setText("\ubc30\ub2ec\uc77c \uc9c0\uc815");
            shippingSectionTitle.setText("\ubc30\ub2ec\uc9c0 \uc815\ubcf4");
        } else {
            freeDelivery.setText("\ubc30\uc1a1\uc0c1\ud488");
            deliveryComment.setText("\ubc30\uc1a1\uc548\ub0b4\uc5d0 \uc18c\uc694\uc77c\uc815\uc744 \ucc38\uace0\ud574\uc8fc\uc138\uc694.");
            possibleSectionTitle.setText("\ubc30\uc1a1\uc77c \uc9c0\uc815");
            shippingSectionTitle.setText("\ubc30\uc1a1\uc9c0 \uc815\ubcf4");
        }
        TextView originalPrice = (TextView) findViewById(R.id.order_object_original_price);
        originalPrice.setPaintFlags(originalPrice.getPaintFlags() | 16);
        originalPrice.setText(FormatUtil.onDecimalFormat(model.getMenuOriginPrice()) + "\uc6d0");
        ((TextView) findViewById(R.id.order_object_sale_price)).setText(FormatUtil.onDecimalFormat(model.getMenuPrice()));
        orderObjectName.setText(model.getMenuName());
        ImageDisplay.getInstance().displayImageLoad(model.getMenuImagePath(), objectImage);
        final AppCompatSpinner orderPossibleDateSpinner = (AppCompatSpinner) findViewById(R.id.order_possible_date);
        ArrayList<String> possibleDate = new ArrayList<>();
        int possibleDateSelectIndex = 0;
        Iterator<DeliveryPossibleDateModel> it = possibleDates.iterator();
        while (it.hasNext()) {
            DeliveryPossibleDateModel dateModel = it.next();
            int userItemCount = Integer.parseInt(dateModel.getUserItemCount());
            int itemCount = Integer.parseInt(dateModel.getItemCount());
            int standardItemCount = Math.min(userItemCount, itemCount);
            possibleDate.add(dateModel.getDisplayDateFormat() + " - \ub0a8\uc740\uc218\ub7c9 " + itemCount + "\uac1c");
            if (standardItemCount == 0) {
                possibleDateSelectIndex++;
            }
        }
        ArrayAdapter<String> possibleDateAdapter = new ArrayAdapter<String>(this, R.layout.spinner_textview, possibleDate) {
            public boolean isEnabled(int position) {
                return true;
            }

            public View getDropDownView(int position, @Nullable View convertView, @NonNull ViewGroup parent) {
                View dropDownView;
                if (convertView == null) {
                    dropDownView = super.getDropDownView(position, convertView, parent);
                } else {
                    dropDownView = super.getDropDownView(position, null, parent);
                }
                if (true == "N".equals(((DeliveryPossibleDateModel) possibleDates.get(position)).getViewYn())) {
                    ((TextView) dropDownView).setTextColor(-7829368);
                }
                return dropDownView;
            }
        };
        orderPossibleDateSpinner.setAdapter((SpinnerAdapter) possibleDateAdapter);
        possibleDateAdapter.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
        orderPossibleDateSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
                if (true == "N".equals(((DeliveryPossibleDateModel) possibleDates.get(position)).getViewYn())) {
                    Toast.makeText(DeliveryActivity.this.getBaseContext(), DeliveryActivity.this.getResources().getString(R.string.impossible_delivery_order_date), 0).show();
                } else {
                    DeliveryActivity.this.refreshObjectInfo(position, possibleDates);
                }
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
        final AppCompatSpinner orderCountSpinner = (AppCompatSpinner) findViewById(R.id.order_count);
        ArrayList<String> arrDailyMaxCount = new ArrayList<>();
        if (possibleDates.size() <= possibleDateSelectIndex) {
            arrDailyMaxCount.add("\uc218\ub7c9 : 0\uac1c");
        } else {
            orderPossibleDateSpinner.setSelection(possibleDateSelectIndex);
            DeliveryPossibleDateModel dateModel2 = possibleDates.get(possibleDateSelectIndex);
            int userItemCount2 = Integer.parseInt(dateModel2.getUserItemCount());
            int itemCount2 = Integer.parseInt(dateModel2.getItemCount());
            for (int i = 0; i < Math.min(userItemCount2, itemCount2); i++) {
                arrDailyMaxCount.add("\uc218\ub7c9 : " + (i + 1) + "\uac1c");
            }
            if (arrDailyMaxCount.size() == 0) {
                arrDailyMaxCount.add("\uc218\ub7c9 : 0\uac1c");
            }
        }
        ArrayAdapter<String> dailyMaxCountAdapter = new ArrayAdapter<>(this, R.layout.spinner_textview, arrDailyMaxCount);
        orderCountSpinner.setAdapter((SpinnerAdapter) dailyMaxCountAdapter);
        dailyMaxCountAdapter.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
        final ArrayList<DeliveryPossibleDateModel> arrayList = possibleDates;
        final DeliveryObjectInfoResultModel deliveryObjectInfoResultModel2 = model;
        orderCountSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
                if (arrayList.size() > 0) {
                    String userItemCount = ((DeliveryPossibleDateModel) arrayList.get(orderPossibleDateSpinner.getSelectedItemPosition())).getUserItemCount();
                    String orderCountText = orderCountSpinner.getSelectedItem().toString();
                    if (true != orderCountText.isEmpty()) {
                        String orderCountText2 = orderCountText.substring("\uc218\ub7c9 : ".length(), orderCountText.length());
                        int orderCount = Integer.parseInt(orderCountText2.substring(0, orderCountText2.indexOf("\uac1c")));
                        if (Integer.parseInt(userItemCount) < orderCount) {
                            Toast.makeText(DeliveryActivity.this.getBaseContext(), "1\uc778\ub2f9 \ucd5c\ub300 \uac00\ub2a5 \uc218\ub7c9\uc744 \ucd08\uacfc\ud558\uc600\uc2b5\ub2c8\ub2e4.", 0).show();
                            orderCountSpinner.setSelection(0, false);
                        }
                        TextView originalPrice = (TextView) DeliveryActivity.this.findViewById(R.id.order_object_original_price);
                        originalPrice.setPaintFlags(originalPrice.getPaintFlags() | 16);
                        originalPrice.setText(FormatUtil.onDecimalFormat(String.valueOf(Integer.valueOf(deliveryObjectInfoResultModel2.getMenuOriginPrice()).intValue() * orderCount)) + "\uc6d0");
                        ((TextView) DeliveryActivity.this.findViewById(R.id.order_object_sale_price)).setText(FormatUtil.onDecimalFormat(String.valueOf(Integer.valueOf(deliveryObjectInfoResultModel2.getMenuPrice()).intValue() * orderCount)));
                    }
                }
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
    }

    /* access modifiers changed from: private */
    public void refreshObjectInfo(int position, ArrayList<DeliveryPossibleDateModel> possibleDates) {
        DeliveryPossibleDateModel dateModel = possibleDates.get(position);
        ((TextView) findViewById(R.id.possible_date_sno)).setText(dateModel.getDateSno());
        ((TextView) findViewById(R.id.object_max_count)).setText("\ub0a8\uc740 \uc218\ub7c9 : " + dateModel.getItemCount() + "\uac1c");
        ((TextView) findViewById(R.id.limit_per_person_count)).setText("1\uc778 \ucd5c\ub300\uac00\ub2a5\uc218\ub7c9 : " + dateModel.getUserItemCount() + "\uac1c");
        AppCompatSpinner orderCountSpinner = (AppCompatSpinner) findViewById(R.id.order_count);
        int dailyMaxCount = Integer.parseInt(dateModel.getUserItemCount());
        int itemCount = Integer.parseInt(dateModel.getItemCount());
        ArrayList<String> arrDailyMaxCount = new ArrayList<>();
        for (int i = 0; i < Math.min(dailyMaxCount, itemCount); i++) {
            arrDailyMaxCount.add("\uc218\ub7c9 : " + (i + 1) + "\uac1c");
        }
        if (arrDailyMaxCount.size() == 0) {
            arrDailyMaxCount.add("\uc218\ub7c9 : 0\uac1c");
        }
        ArrayAdapter<String> dailyMaxCountAdapter = (ArrayAdapter) orderCountSpinner.getAdapter();
        dailyMaxCountAdapter.clear();
        dailyMaxCountAdapter.addAll(arrDailyMaxCount);
    }

    /* access modifiers changed from: private */
    public void setActiveAddressPage() {
        this.customViewPager.setCurrentItem(2);
        if (this.deliveryShippingAddressRecentModels != null && this.deliveryShippingAddressRecentModels.size() > 0) {
            this.customViewPager.setCurrentItem(1);
        }
        if (this.deliveryShippingAddressDefaultModel != null && this.deliveryShippingAddressDefaultModel.getAddress() != null) {
            this.customViewPager.setCurrentItem(0);
        }
    }

    /* access modifiers changed from: private */
    public void requestDeliveryPossibleArea() {
        new DeliveryPossibleAreaApi(this).request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                DeliveryActivity.this.deliveryPossibleAreaModels = ((DeliveryPossibleAreaModel) result).getResult_list();
                ((DeliveryDirectlyAddressFragment) ((ShippingAddressPager) DeliveryActivity.this.customViewPager.getAdapter()).getItem(2)).setData(DeliveryActivity.this.deliveryPossibleAreaModels);
            }

            public void onFailure(Exception exception) {
                super.onFailure(exception);
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }

    /* access modifiers changed from: private */
    public String requestThirdPartyContent(String urlStr) {
        StringBuilder output = new StringBuilder();
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
            if (conn != null) {
                conn.setConnectTimeout(10000);
                conn.setRequestMethod(HttpRequest.METHOD_GET);
                conn.setDoInput(true);
                conn.setDoOutput(true);
                if (conn.getResponseCode() == 200) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                    while (true) {
                        String line = reader.readLine();
                        if (line == null) {
                            break;
                        }
                        output.append(line + "\n");
                    }
                    reader.close();
                    conn.disconnect();
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return output.toString();
    }

    private String getDayStr(String dateStr) {
        String[] days = {"", "\uc77c", "\uc6d4", "\ud654", "\uc218", "\ubaa9", "\uae08", "\ud1a0"};
        try {
            Calendar calender = Calendar.getInstance();
            calender.setTime(new SimpleDateFormat("yyyy-MM-dd").parse(dateStr));
            return "(" + days[calender.get(7)] + ")";
        } catch (ParseException e) {
            e.printStackTrace();
            System.out.println(getClass().getName() + " " + e.toString());
            return "";
        }
    }

    public void onEventMainThread(CardViewStatusEvent event) {
        String message = "";
        switch (((CardView) findViewById(R.id.cardView)).getCardStatus()) {
            case 1:
                message = "\uba3c\uc800 \uce74\ub4dc\ub97c \ub4f1\ub85d\ud558\uc154\uc57c \uacb0\uc81c\uac00 \uac00\ub2a5\ud569\ub2c8\ub2e4.";
                break;
            case 2:
                message = "\uacb0\uc81c\ud560 \ub9e4\uc7a5\uc744 \uc120\ud0dd\ud558\uc138\uc694.";
                break;
            case 3:
                message = "\uce74\ub4dc\ub97c \ubc00\uc5b4\uc11c \uacb0\uc81c\uc694\uccad\ud558\uc138\uc694.";
                break;
            case 4:
                message = "\uac00\uc785\uc2dc \uc124\uc815\ud558\uc2e0 \ube44\ubc00\ubc88\ud638\ub97c \uc785\ub825\ud558\uc138\uc694.";
                break;
            case 5:
                message = "\uce74\uc6b4\ud130\uc5d0 \ubc14\ucf54\ub4dc\ub97c \uc81c\uc2dc\ud574 \uc8fc\uc138\uc694.";
                break;
            case 6:
                message = "";
                break;
        }
        if (message == null || message.isEmpty()) {
            findViewById(R.id.titleGuideLabel).setVisibility(8);
            findViewById(R.id.titleGuideImageView).setVisibility(8);
        } else {
            findViewById(R.id.titleGuideLabel).setVisibility(0);
            findViewById(R.id.titleGuideImageView).setVisibility(0);
        }
        ((TextView) findViewById(R.id.titleGuideLabel)).setText(message);
    }

    public void onEventMainThread(GuideCloseEvent event) {
    }

    public void onEventMainThread(CardUpdateEvent event) {
        setCardInfo();
    }

    public void onEventMainThread(CardSlideEvent event) {
        if (event.isOpen()) {
            findViewById(R.id.dimBar).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_in));
            findViewById(R.id.dimBar).setVisibility(0);
            return;
        }
        findViewById(R.id.dimBar).startAnimation(AnimationUtils.loadAnimation(this, R.anim.fade_out));
        findViewById(R.id.dimBar).setVisibility(8);
    }

    public void onEventMainThread(DeliveryActivityFinishEvent event) {
        finish(false);
    }
}