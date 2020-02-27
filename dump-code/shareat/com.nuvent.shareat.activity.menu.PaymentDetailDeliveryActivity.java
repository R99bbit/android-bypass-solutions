package com.nuvent.shareat.activity.menu;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.support.v7.widget.AppCompatSpinner;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.SpinnerAdapter;
import android.widget.TextView;
import android.widget.Toast;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.DeliveryPaymentCancelApi;
import com.nuvent.shareat.api.DeliveryPossibleAreaApi;
import com.nuvent.shareat.api.DeliveryShippingAddressUpdateApi;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.card.PaymentDetailApi;
import com.nuvent.shareat.dialog.ZipCodeDialog;
import com.nuvent.shareat.dialog.ZipCodeDialog.callback;
import com.nuvent.shareat.manager.sns.BaseSnsManager;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.MyPaymentModel;
import com.nuvent.shareat.model.delivery.DeliveryPaymentCancelResultModel;
import com.nuvent.shareat.model.delivery.DeliveryPossibleAreaDetailModel;
import com.nuvent.shareat.model.delivery.DeliveryPossibleAreaModel;
import com.nuvent.shareat.model.payment.PaymentDetailModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import net.xenix.android.widget.FontEditTextView;
import net.xenix.util.FormatUtil;
import net.xenix.util.ImageDisplay;

public class PaymentDetailDeliveryActivity extends MainActionBarActivity {
    private ArrayList<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> area = new ArrayList<>();
    /* access modifiers changed from: private */
    public ArrayList<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> deliveryPossibleAreaModels;
    /* access modifiers changed from: private */
    public Map<String, ArrayList<DeliveryPossibleAreaDetailModel>> guMap;
    /* access modifiers changed from: private */
    public AppCompatSpinner guSpinner;
    private AppCompatSpinner orderMobileNumSpinner;
    /* access modifiers changed from: private */
    public PaymentDetailModel paymentDetailModel;
    /* access modifiers changed from: private */
    public MyPaymentModel paymentModel;
    private AppCompatSpinner receiverMobileNumSpinner;
    /* access modifiers changed from: private */
    public AppCompatSpinner siSpinner;
    /* access modifiers changed from: private */
    public ZipCodeDialog zipCodeDialog;

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        GAEvent.onGAScreenView(this, R.string.ga_delivery_receipt_view);
        setContentView(R.layout.activity_payment_detail_delivery_layout, 5);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\uc601\uc218\uc99d");
        this.paymentModel = (MyPaymentModel) getIntent().getSerializableExtra("data");
        requestPayHistoryInfo();
        requestDeliveryPossibleArea();
        setSpinner();
        bidingClickEvent();
    }

    /* access modifiers changed from: protected */
    public void onDestroy() {
        super.onDestroy();
    }

    public void onClickBack(View view) {
        setResult(-1);
        finish();
    }

    public void onBackPressed() {
        setResult(-1);
        finish();
    }

    private void setSpinner() {
        this.siSpinner = (AppCompatSpinner) findViewById(R.id.si);
        this.siSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
                ArrayList<String> gu = new ArrayList<>();
                if (PaymentDetailDeliveryActivity.this.siSpinner.getSelectedItem() != null) {
                    ArrayAdapter<String> guAdapter = (ArrayAdapter) PaymentDetailDeliveryActivity.this.guSpinner.getAdapter();
                    guAdapter.clear();
                    Iterator<DeliveryPossibleAreaDetailModel> it = ((ArrayList) PaymentDetailDeliveryActivity.this.guMap.get((String) PaymentDetailDeliveryActivity.this.siSpinner.getSelectedItem())).iterator();
                    while (it.hasNext()) {
                        gu.add(it.next().getLocalName());
                    }
                    guAdapter.addAll(gu);
                }
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
        this.guSpinner = (AppCompatSpinner) findViewById(R.id.gu);
        this.guSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
        this.orderMobileNumSpinner = (AppCompatSpinner) findViewById(R.id.update_order_mobile_num);
        ArrayList<String> mobileNums = new ArrayList<>();
        mobileNums.add("010");
        mobileNums.add("011");
        mobileNums.add("017");
        mobileNums.add("018");
        mobileNums.add("070");
        mobileNums.add(BaseSnsManager.SNS_LOGIN_TYPE_KAKAO);
        mobileNums.add("031");
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, R.layout.spinner_textview, mobileNums);
        this.orderMobileNumSpinner.setAdapter((SpinnerAdapter) adapter);
        adapter.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
        this.orderMobileNumSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
        this.receiverMobileNumSpinner = (AppCompatSpinner) findViewById(R.id.receiver_mobile_num);
        ArrayAdapter<String> adapter2 = new ArrayAdapter<>(this, R.layout.spinner_textview, mobileNums);
        this.receiverMobileNumSpinner.setAdapter((SpinnerAdapter) adapter2);
        adapter2.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
        this.receiverMobileNumSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
    }

    private void bidingClickEvent() {
        findViewById(R.id.payment_cancel).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                String fullAddress;
                String orderName = PaymentDetailDeliveryActivity.this.paymentDetailModel.getOrder_name() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getOrder_name();
                String orderPhone = PaymentDetailDeliveryActivity.this.paymentDetailModel.getOrder_phone() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getOrder_phone();
                String receiveName = PaymentDetailDeliveryActivity.this.paymentDetailModel.getReceive_name() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getReceive_name();
                if (PaymentDetailDeliveryActivity.this.paymentDetailModel.getZip_code() == null || true == PaymentDetailDeliveryActivity.this.paymentDetailModel.getZip_code().isEmpty()) {
                    fullAddress = "" + (PaymentDetailDeliveryActivity.this.paymentDetailModel.getAddress() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getAddress());
                } else {
                    fullAddress = "(" + PaymentDetailDeliveryActivity.this.paymentDetailModel.getZip_code() + ") ";
                }
                String fullAddress2 = fullAddress + (PaymentDetailDeliveryActivity.this.paymentDetailModel.getAddress_rest() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getAddress_rest());
                String receivePhone = PaymentDetailDeliveryActivity.this.paymentDetailModel.getReceive_phone() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getReceive_phone();
                int discount = Integer.valueOf(PaymentDetailDeliveryActivity.this.paymentDetailModel.getMenu_orgin_price() * PaymentDetailDeliveryActivity.this.paymentDetailModel.getCount()).intValue() - Integer.valueOf(PaymentDetailDeliveryActivity.this.paymentDetailModel.getPay_real()).intValue();
                PaymentDetailDeliveryActivity paymentDetailDeliveryActivity = PaymentDetailDeliveryActivity.this;
                PaymentDetailDeliveryActivity paymentDetailDeliveryActivity2 = PaymentDetailDeliveryActivity.this;
                Object[] objArr = new Object[11];
                objArr[0] = PaymentDetailDeliveryActivity.this.paymentDetailModel.getMenu_name() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getMenu_name();
                objArr[1] = String.valueOf(PaymentDetailDeliveryActivity.this.paymentDetailModel.getCount());
                objArr[2] = FormatUtil.onDecimalFormat(String.valueOf(discount)) + "\uc6d0";
                objArr[3] = FormatUtil.onDecimalFormat(PaymentDetailDeliveryActivity.this.paymentDetailModel.getPay_real()) + "\uc6d0";
                objArr[4] = orderName;
                objArr[5] = orderPhone;
                objArr[6] = receiveName;
                objArr[7] = true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(PaymentDetailDeliveryActivity.this.paymentDetailModel.getMethod()) ? "\ubc30\ub2ec" : "\ubc30\uc1a1";
                objArr[8] = PaymentDetailDeliveryActivity.this.paymentDetailModel.getDisplayDateFormat();
                objArr[9] = fullAddress2;
                objArr[10] = receivePhone;
                paymentDetailDeliveryActivity.showCustomConfirmDialog("[\uc8fc\ubb38/\uacb0\uc81c \ucde8\uc18c]", paymentDetailDeliveryActivity2.getString(R.string.payment_cancel_alert_message, objArr), "\ucde8\uc18c", "\ud655\uc778", new Runnable() {
                    public void run() {
                    }
                }, new Runnable() {
                    public void run() {
                        GAEvent.onGaEvent((Activity) PaymentDetailDeliveryActivity.this, (int) R.string.ga_delivery_payment_detail_view, (int) R.string.ga_ev_click, (int) R.string.ga_delivery_payment_detail_cancel);
                        PaymentDetailDeliveryActivity.this.requestPaymentCancel();
                    }
                });
            }
        });
        findViewById(R.id.update_order_info).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                PaymentDetailDeliveryActivity.this.findViewById(R.id.order_info_update_layout).setVisibility(0);
            }
        });
        findViewById(R.id.search_zip_code).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                PaymentDetailDeliveryActivity.this.zipCodeDialog = new ZipCodeDialog(PaymentDetailDeliveryActivity.this);
                PaymentDetailDeliveryActivity.this.zipCodeDialog.setCallback(new callback() {
                    public void callback(final String arg1, final String arg2, final String arg3) {
                        PaymentDetailDeliveryActivity.this.runOnUiThread(new Runnable() {
                            public void run() {
                                ((TextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.zip_code)).setText(arg1);
                                String address = arg2;
                                if (!arg3.isEmpty()) {
                                    address = address + "(" + arg3 + ")";
                                }
                                PaymentDetailDeliveryActivity.this.findViewById(R.id.update_receiver_detail_address).clearFocus();
                                PaymentDetailDeliveryActivity.this.findViewById(R.id.update_receiver_detail_address).requestFocus();
                                ((TextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.update_receiver_detail_address)).setText(address);
                                ((FontEditTextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.update_receiver_detail_address)).setSelection(address.length());
                            }
                        });
                    }
                });
                PaymentDetailDeliveryActivity.this.zipCodeDialog.show();
            }
        });
        findViewById(R.id.update_receiver_info).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                PaymentDetailDeliveryActivity.this.findViewById(R.id.receiver_info_update_layout).setVisibility(0);
                PaymentDetailDeliveryActivity.this.findViewById(R.id.update_receiver_name).requestFocus();
                if (true == PaymentDetailModel.DELIVERY_METHOD_POST.equals(PaymentDetailDeliveryActivity.this.paymentDetailModel.getMethod())) {
                    PaymentDetailDeliveryActivity.this.findViewById(R.id.zip_code_layout).setVisibility(0);
                    PaymentDetailDeliveryActivity.this.findViewById(R.id.default_address_layout).setVisibility(8);
                }
                LinearLayout llReceiverInfoUpdateLayout = (LinearLayout) PaymentDetailDeliveryActivity.this.findViewById(R.id.receiver_info_update_layout);
                llReceiverInfoUpdateLayout.measure(-1, -1);
                int measuredHeight = llReceiverInfoUpdateLayout.getMeasuredHeight();
                ((ScrollView) PaymentDetailDeliveryActivity.this.findViewById(R.id.root_scroll_view)).post(new Runnable() {
                    public void run() {
                        ((ScrollView) PaymentDetailDeliveryActivity.this.findViewById(R.id.root_scroll_view)).fullScroll(130);
                    }
                });
            }
        });
        findViewById(R.id.order_update_confirm).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                String fullAddress;
                String str;
                final TextView orderName = (TextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.update_order_name);
                final TextView phoneNumber = (TextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.update_order_phone_number);
                String phoneNum = ((AppCompatSpinner) PaymentDetailDeliveryActivity.this.findViewById(R.id.update_order_mobile_num)).getSelectedItem().toString() + phoneNumber.getText().toString();
                if (true == orderName.getText().toString().isEmpty()) {
                    PaymentDetailDeliveryActivity.this.showDialog("\uc8fc\ubb38\uc790 \uc815\ubcf4(\uc774\ub984) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            orderName.requestFocus();
                        }
                    });
                } else if (true == phoneNumber.getText().toString().isEmpty()) {
                    PaymentDetailDeliveryActivity.this.showDialog("\uc8fc\ubb38\uc790 \uc815\ubcf4(\uc804\ud654\ubc88\ud638) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            phoneNumber.requestFocus();
                        }
                    });
                } else {
                    String receiveName = PaymentDetailDeliveryActivity.this.paymentDetailModel.getReceive_name() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getReceive_name();
                    if (PaymentDetailDeliveryActivity.this.paymentDetailModel.getZip_code() == null || true == PaymentDetailDeliveryActivity.this.paymentDetailModel.getZip_code().isEmpty()) {
                        fullAddress = "" + (PaymentDetailDeliveryActivity.this.paymentDetailModel.getAddress() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getAddress());
                    } else {
                        fullAddress = "(" + PaymentDetailDeliveryActivity.this.paymentDetailModel.getZip_code() + ")";
                    }
                    String fullAddress2 = fullAddress + (PaymentDetailDeliveryActivity.this.paymentDetailModel.getAddress_rest() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getAddress_rest());
                    String receivePhone = PaymentDetailDeliveryActivity.this.paymentDetailModel.getReceive_phone() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getReceive_phone();
                    PaymentDetailDeliveryActivity paymentDetailDeliveryActivity = PaymentDetailDeliveryActivity.this;
                    PaymentDetailDeliveryActivity paymentDetailDeliveryActivity2 = PaymentDetailDeliveryActivity.this;
                    Object[] objArr = new Object[8];
                    objArr[0] = orderName.getText().toString();
                    objArr[1] = phoneNum;
                    objArr[2] = receiveName;
                    objArr[3] = true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(PaymentDetailDeliveryActivity.this.paymentDetailModel.getMethod()) ? "\ubc30\ub2ec" : "\ubc30\uc1a1";
                    objArr[4] = PaymentDetailDeliveryActivity.this.paymentDetailModel.getDisplayDateFormat();
                    objArr[5] = fullAddress2;
                    objArr[6] = receivePhone;
                    if (true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(PaymentDetailDeliveryActivity.this.paymentDetailModel.getMethod())) {
                        str = "\ubc30\ub2ec";
                    } else {
                        str = "\ubc30\uc1a1";
                    }
                    objArr[7] = str;
                    paymentDetailDeliveryActivity.showCustomConfirmDialog("[\uc8fc\ubb38/\uacb0\uc81c \ubcc0\uacbd]", paymentDetailDeliveryActivity2.getString(R.string.payment_order_update_alert_message, objArr), "\ucde8\uc18c", "\ud655\uc778", new Runnable() {
                        public void run() {
                        }
                    }, new Runnable() {
                        public void run() {
                            GAEvent.onGaEvent((Activity) PaymentDetailDeliveryActivity.this, (int) R.string.ga_delivery_payment_detail_view, (int) R.string.ga_ev_click, (int) R.string.ga_delivery_payment_detail_order_info_update);
                            PaymentDetailDeliveryActivity.this.findViewById(R.id.order_info_update_layout).setVisibility(8);
                            PaymentDetailDeliveryActivity.this.requestUpdateOrderInfo();
                        }
                    });
                }
            }
        });
        findViewById(R.id.order_update_cancel).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                PaymentDetailDeliveryActivity.this.findViewById(R.id.order_info_update_layout).setVisibility(8);
            }
        });
        findViewById(R.id.receiver_update_confirm).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                String fullAddress;
                String str;
                TextView receiverName = (TextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.update_receiver_name);
                AppCompatSpinner mobileNum = (AppCompatSpinner) PaymentDetailDeliveryActivity.this.findViewById(R.id.receiver_mobile_num);
                final TextView phoneNumber = (TextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.update_receiver_phone_number);
                final TextView receiverDetailAddress = (TextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.update_receiver_detail_address);
                TextView requestMessageUpdate = (TextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.receiver_inquire_update);
                TextView zipCode = (TextView) PaymentDetailDeliveryActivity.this.findViewById(R.id.zip_code);
                if (true == PaymentDetailModel.DELIVERY_METHOD_POST.equals(PaymentDetailDeliveryActivity.this.paymentDetailModel.getMethod()) && true == zipCode.getText().toString().isEmpty()) {
                    final TextView textView = zipCode;
                    PaymentDetailDeliveryActivity.this.showDialog("\ubc30\uc1a1\uc9c0 \uc815\ubcf4(\uc6b0\ud3b8\ubc88\ud638) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            textView.requestFocus();
                        }
                    });
                } else if (true == receiverName.getText().toString().isEmpty()) {
                    final TextView textView2 = receiverName;
                    PaymentDetailDeliveryActivity.this.showDialog("\ubc30\uc1a1\uc9c0 \uc815\ubcf4(\uc774\ub984) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            textView2.requestFocus();
                        }
                    });
                } else if (true == phoneNumber.getText().toString().isEmpty()) {
                    PaymentDetailDeliveryActivity.this.showDialog("\ubc30\uc1a1\uc9c0 \uc815\ubcf4(\uc804\ud654\ubc88\ud638) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            phoneNumber.requestFocus();
                        }
                    });
                } else if (true == receiverDetailAddress.getText().toString().isEmpty()) {
                    PaymentDetailDeliveryActivity.this.showDialog("\ubc30\uc1a1\uc9c0 \uc815\ubcf4(\uc0c1\uc138\uc8fc\uc18c) \uc785\ub825 \ub0b4\uc6a9\uc744 \ud655\uc778\ud558\uc5ec \uc8fc\uc138\uc694!", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            receiverDetailAddress.requestFocus();
                        }
                    });
                } else {
                    String str2 = mobileNum.getSelectedItem().toString() + phoneNumber.getText().toString();
                    String orderName = PaymentDetailDeliveryActivity.this.paymentDetailModel.getOrder_name() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getOrder_name();
                    String orderPhone = PaymentDetailDeliveryActivity.this.paymentDetailModel.getOrder_phone() == null ? "" : PaymentDetailDeliveryActivity.this.paymentDetailModel.getOrder_phone();
                    if (!zipCode.getText().toString().isEmpty()) {
                        fullAddress = "(" + zipCode.getText().toString() + ")";
                    } else {
                        fullAddress = ("" + PaymentDetailDeliveryActivity.this.siSpinner.getSelectedItem().toString()) + (PaymentDetailDeliveryActivity.this.guSpinner.getCount() > 0 ? PaymentDetailDeliveryActivity.this.guSpinner.getSelectedItem() : "");
                    }
                    String fullAddress2 = fullAddress + receiverDetailAddress.getText().toString();
                    PaymentDetailDeliveryActivity paymentDetailDeliveryActivity = PaymentDetailDeliveryActivity.this;
                    PaymentDetailDeliveryActivity paymentDetailDeliveryActivity2 = PaymentDetailDeliveryActivity.this;
                    Object[] objArr = new Object[9];
                    objArr[0] = orderName;
                    objArr[1] = orderPhone;
                    objArr[2] = receiverName.getText().toString();
                    objArr[3] = true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(PaymentDetailDeliveryActivity.this.paymentDetailModel.getMethod()) ? "\ubc30\ub2ec" : "\ubc30\uc1a1";
                    objArr[4] = PaymentDetailDeliveryActivity.this.paymentDetailModel.getDisplayDateFormat();
                    objArr[5] = fullAddress2;
                    objArr[6] = phoneNumber.getText().toString();
                    objArr[7] = requestMessageUpdate.getText().toString();
                    if (true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(PaymentDetailDeliveryActivity.this.paymentDetailModel.getMethod())) {
                        str = "\ubc30\ub2ec";
                    } else {
                        str = "\ubc30\uc1a1";
                    }
                    objArr[8] = str;
                    paymentDetailDeliveryActivity.showCustomConfirmDialog("[\uc8fc\ubb38/\uacb0\uc81c \ubcc0\uacbd]", paymentDetailDeliveryActivity2.getString(R.string.payment_receiver_update_alert_message, objArr), "\ucde8\uc18c", "\ud655\uc778", new Runnable() {
                        public void run() {
                        }
                    }, new Runnable() {
                        public void run() {
                            GAEvent.onGaEvent((Activity) PaymentDetailDeliveryActivity.this, (int) R.string.ga_delivery_payment_detail_view, (int) R.string.ga_ev_click, (int) R.string.ga_delivery_payment_detail_receiver_info_update);
                            PaymentDetailDeliveryActivity.this.findViewById(R.id.receiver_info_update_layout).setVisibility(8);
                            PaymentDetailDeliveryActivity.this.requestUpdateReceiverInfo();
                        }
                    });
                }
            }
        });
        findViewById(R.id.receiver_update_cancel).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                PaymentDetailDeliveryActivity.this.findViewById(R.id.receiver_info_update_layout).setVisibility(8);
                PaymentDetailDeliveryActivity.this.findViewById(R.id.scroll_child_layout).setY(0.0f);
            }
        });
        findViewById(R.id.emailButton).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                PaymentDetailDeliveryActivity.this.startActivity(new Intent("android.intent.action.VIEW", Uri.parse(String.format(ApiUrl.RECENT_DO, new Object[]{ShareatApp.getInstance().getUserNum(), PaymentDetailDeliveryActivity.this.paymentModel.pay_group, PaymentDetailDeliveryActivity.this.paymentModel.order_id}))));
            }
        });
    }

    /* access modifiers changed from: private */
    public void requestUpdateOrderInfo() {
        DeliveryShippingAddressUpdateApi request = new DeliveryShippingAddressUpdateApi(this);
        request.addParam("phone_os", "A");
        request.addParam("delivery_order_id", String.valueOf(this.paymentDetailModel.getDelivery_order_id()));
        request.addParam("order_name", ((TextView) findViewById(R.id.update_order_name)).getText().toString());
        request.addParam("order_phone", ((AppCompatSpinner) findViewById(R.id.update_order_mobile_num)).getSelectedItem().toString() + ((TextView) findViewById(R.id.update_order_phone_number)).getText().toString());
        request.addParam("request_message", ((TextView) findViewById(R.id.receiver_inquire)).getText().toString());
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                BaseResultModel resultModel = (BaseResultModel) result;
                if (true == "Y".equals(resultModel.getResult()) && true == "200".equals(resultModel.getResult_code())) {
                    PaymentDetailDeliveryActivity.this.resetOrderAndReceiverInfo();
                    PaymentDetailDeliveryActivity.this.requestPayHistoryInfo();
                }
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
    public void requestUpdateReceiverInfo() {
        DeliveryShippingAddressUpdateApi request = new DeliveryShippingAddressUpdateApi(this);
        AppCompatSpinner si = (AppCompatSpinner) findViewById(R.id.si);
        AppCompatSpinner gu = (AppCompatSpinner) findViewById(R.id.gu);
        TextView receiverDetailAddress = (TextView) findViewById(R.id.update_receiver_detail_address);
        request.addParam("phone_os", "A");
        request.addParam("delivery_order_id", String.valueOf(this.paymentDetailModel.getDelivery_order_id()));
        request.addParam("receive_name", ((TextView) findViewById(R.id.update_receiver_name)).getText().toString());
        request.addParam("receive_phone", ((AppCompatSpinner) findViewById(R.id.receiver_mobile_num)).getSelectedItem().toString() + ((TextView) findViewById(R.id.update_receiver_phone_number)).getText().toString());
        request.addParam("request_message", ((TextView) findViewById(R.id.receiver_inquire_update)).getText().toString());
        request.addParam("zip_code", ((TextView) findViewById(R.id.zip_code)).getText().toString());
        String defaultAddress = "";
        if (!PaymentDetailModel.DELIVERY_METHOD_POST.equals(this.paymentDetailModel.getMethod())) {
            if (si.getCount() > 0) {
                defaultAddress = defaultAddress + si.getSelectedItem().toString();
            }
            if (gu.getCount() > 0) {
                defaultAddress = defaultAddress + " " + gu.getSelectedItem().toString();
            }
        }
        request.addParam("address", defaultAddress);
        request.addParam("address_rest", receiverDetailAddress.getText().toString());
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                BaseResultModel resultModel = (BaseResultModel) result;
                if (true == "Y".equals(resultModel.getResult()) && true == "200".equals(resultModel.getResult_code())) {
                    PaymentDetailDeliveryActivity.this.resetOrderAndReceiverInfo();
                    PaymentDetailDeliveryActivity.this.requestPayHistoryInfo();
                }
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
    public void requestPaymentCancel() {
        DeliveryPaymentCancelApi request = new DeliveryPaymentCancelApi(this);
        request.addGetParam(String.format("?orderId=%s&phone_os=A", new Object[]{this.paymentModel.getOrder_id()}));
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                DeliveryPaymentCancelResultModel deliveryPaymentCancelResultModel = (DeliveryPaymentCancelResultModel) result;
                if (deliveryPaymentCancelResultModel.getErr_msg() == null || deliveryPaymentCancelResultModel.getErr_msg().isEmpty()) {
                    Toast.makeText(PaymentDetailDeliveryActivity.this.getBaseContext(), "\uacb0\uc81c\ucde8\uc18c\uac00 \uc815\uc0c1\uc801\uc73c\ub85c \uc644\ub8cc\ub418\uc5c8\uc2b5\ub2c8\ub2e4", 1).show();
                    PaymentDetailDeliveryActivity.this.setResult(-1);
                    PaymentDetailDeliveryActivity.this.finish();
                    return;
                }
                Toast.makeText(PaymentDetailDeliveryActivity.this.getBaseContext(), deliveryPaymentCancelResultModel.getErr_msg(), 1).show();
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
    public void requestPayHistoryInfo() {
        new PaymentDetailApi(this, ApiUrl.PAYMENT_HISTORY_INFO + String.format("?pay_group=%s&order_id=%s&view_type=%s", new Object[]{this.paymentModel.pay_group, this.paymentModel.order_id, this.paymentModel.getPay_method()})).request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onResult(Object result) {
                PaymentDetailDeliveryActivity.this.paymentDetailModel = (PaymentDetailModel) result;
                PaymentDetailDeliveryActivity.this.setData();
            }

            public void onFailure(Exception exception) {
                PaymentDetailDeliveryActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        PaymentDetailDeliveryActivity.this.requestPayHistoryInfo();
                    }
                });
            }
        });
    }

    private void requestDeliveryPossibleArea() {
        new DeliveryPossibleAreaApi(this).request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onProgress(int bytesWritten, int totalSize) {
                super.onProgress(bytesWritten, totalSize);
            }

            public void onResult(Object result) {
                PaymentDetailDeliveryActivity.this.deliveryPossibleAreaModels = ((DeliveryPossibleAreaModel) result).getResult_list();
                PaymentDetailDeliveryActivity.this.setPossibleAreaSpinner(PaymentDetailDeliveryActivity.this.deliveryPossibleAreaModels);
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
    public void resetOrderAndReceiverInfo() {
        ((TextView) findViewById(R.id.update_order_name)).setText("");
        ((AppCompatSpinner) findViewById(R.id.update_order_mobile_num)).setSelection(0);
        ((TextView) findViewById(R.id.update_order_phone_number)).setText("");
        ((TextView) findViewById(R.id.update_receiver_name)).setText("");
        ((TextView) findViewById(R.id.zip_code)).setText("");
        ((AppCompatSpinner) findViewById(R.id.si)).setSelection(0);
        ((AppCompatSpinner) findViewById(R.id.gu)).setSelection(0);
        ((TextView) findViewById(R.id.update_receiver_detail_address)).setText("");
        ((AppCompatSpinner) findViewById(R.id.receiver_mobile_num)).setSelection(0);
        ((TextView) findViewById(R.id.update_receiver_phone_number)).setText("");
    }

    /* access modifiers changed from: private */
    public void setData() {
        String receive_phone;
        String address_rest;
        ImageView menuImage = (ImageView) findViewById(R.id.object_image);
        TextView orderCount = (TextView) findViewById(R.id.order_count_text);
        TextView orderObjectName = (TextView) findViewById(R.id.order_object_name);
        TextView orderObjectSalePrice = (TextView) findViewById(R.id.order_object_sale_price);
        TextView orderObjectOriginalPrice = (TextView) findViewById(R.id.order_object_original_price);
        TextView orderNameText = (TextView) findViewById(R.id.order_name_fix);
        TextView orderPhoneNumber = (TextView) findViewById(R.id.order_phone_number);
        TextView orderNameTemp = (TextView) findViewById(R.id.temp_order_name);
        TextView receiverName = (TextView) findViewById(R.id.receiver_name_fix);
        TextView receiverNameTemp = (TextView) findViewById(R.id.temp_receiver_name);
        TextView receiverPhoneNumber = (TextView) findViewById(R.id.receiver_phone_number);
        TextView address = (TextView) findViewById(R.id.address_fix);
        TextView addressRest = (TextView) findViewById(R.id.address_rest_fix);
        TextView orderFreeDelivery = (TextView) findViewById(R.id.order_object_no_charge);
        TextView orderDate = (TextView) findViewById(R.id.delivery_order_date);
        TextView requestMessage = (TextView) findViewById(R.id.receiver_inquire);
        TextView requestMessageTitle = (TextView) findViewById(R.id.receiver_inquire_title);
        TextView requestMessageUpdate = (TextView) findViewById(R.id.receiver_inquire_update);
        if (true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(this.paymentDetailModel.getMethod())) {
            orderFreeDelivery.setText("\ubc30\ub2ec\uc0c1\ud488");
            requestMessageTitle.setText("\ubc30\ub2ec\uc2dc \uc694\uccad\uc0ac\ud56d");
            requestMessage.setHint("\ubc30\ub2ec\uc2dc \uc694\uccad\uc0ac\ud56d");
            requestMessageUpdate.setHint("\ubc30\ub2ec\uc2dc \uc694\uccad\uc0ac\ud56d");
        } else {
            orderFreeDelivery.setText("\ubc30\uc1a1\uc0c1\ud488");
            requestMessageTitle.setText("\ubc30\uc1a1\uc2dc \uc694\uccad\uc0ac\ud56d");
            requestMessage.setHint("\ubc30\uc1a1\uc2dc \uc694\uccad\uc0ac\ud56d");
            requestMessageUpdate.setHint("\ubc30\uc1a1\uc2dc \uc694\uccad\uc0ac\ud56d");
        }
        ImageDisplay.getInstance().displayImageLoad(this.paymentDetailModel.getMenu_image_path(), menuImage);
        orderCount.setText("\uc218\ub7c9 : " + String.valueOf(this.paymentDetailModel.getCount()) + "\uac1c");
        orderObjectName.setText(this.paymentDetailModel.getMenu_name());
        orderObjectSalePrice.setText(String.valueOf(this.paymentDetailModel.getPay_real()));
        orderObjectOriginalPrice.setText(String.valueOf(this.paymentDetailModel.getMenu_orgin_price() * this.paymentDetailModel.getCount()) + "\uc6d0");
        orderObjectOriginalPrice.setPaintFlags(orderObjectOriginalPrice.getPaintFlags() | 16);
        String orderName = this.paymentDetailModel.getOrder_name() == null ? "" : this.paymentDetailModel.getOrder_name();
        orderNameText.setText(orderName);
        orderNameTemp.setText(orderName);
        orderPhoneNumber.setText(this.paymentDetailModel.getOrder_phone() == null ? "" : this.paymentDetailModel.getOrder_phone());
        String receiveName = this.paymentDetailModel.getReceive_name() == null ? "" : this.paymentDetailModel.getReceive_name();
        receiverName.setText(receiveName);
        receiverNameTemp.setText(receiveName);
        if (this.paymentDetailModel.getReceive_phone() == null) {
            receive_phone = "";
        } else {
            receive_phone = this.paymentDetailModel.getReceive_phone();
        }
        receiverPhoneNumber.setText(receive_phone);
        orderDate.setText(this.paymentDetailModel.getDisplayDateFormat());
        requestMessage.setText(this.paymentDetailModel.getRequest_message());
        requestMessageUpdate.setText(this.paymentDetailModel.getRequest_message());
        if (this.paymentDetailModel.getZip_code() == null || true == this.paymentDetailModel.getZip_code().isEmpty()) {
            address.setText(this.paymentDetailModel.getAddress() == null ? "" : this.paymentDetailModel.getAddress());
        } else {
            address.setText("(" + this.paymentDetailModel.getZip_code() + ")");
        }
        if (this.paymentDetailModel.getAddress_rest() == null) {
            address_rest = "";
        } else {
            address_rest = this.paymentDetailModel.getAddress_rest();
        }
        addressRest.setText(address_rest);
        TextView deliveryStatus = (TextView) findViewById(R.id.delivery_status);
        TextView deliveryStep1 = (TextView) findViewById(R.id.delivery_step1);
        TextView deliveryStep2 = (TextView) findViewById(R.id.delivery_step2);
        TextView deliveryStep3 = (TextView) findViewById(R.id.delivery_step3);
        TextView deliveryStep4 = (TextView) findViewById(R.id.delivery_step4);
        TextView deliveryStep5 = (TextView) findViewById(R.id.delivery_step5);
        if (true == PaymentDetailModel.DELIVERY_METHOD_QUICK.equals(this.paymentDetailModel.getMethod())) {
            deliveryStatus.setText("\ubc30\ub2ec \uc0c1\ud0dc");
            deliveryStep1.setText("\uacb0\uc81c\uc644\ub8cc");
            deliveryStep2.setText("\uc0c1\ud488\uc900\ube44\uc911");
            deliveryStep3.setText("\ubc30\ub2ec\uc900\ube44\uc911");
            deliveryStep4.setText("\ubc30\ub2ec\uc911");
            deliveryStep5.setText("\ubc30\ub2ec\uc644\ub8cc");
        } else {
            deliveryStatus.setText("\ubc30\uc1a1 \uc0c1\ud0dc");
            deliveryStep1.setText("\uacb0\uc81c\uc644\ub8cc");
            deliveryStep2.setText("\uc0c1\ud488\uc900\ube44\uc911");
            deliveryStep3.setText("\ubc30\uc1a1\uc900\ube44\uc911");
            deliveryStep4.setText("\ubc30\uc1a1\uc911");
            deliveryStep5.setText("\ubc30\uc1a1\uc644\ub8cc");
        }
        if ("PAYED".equals(this.paymentDetailModel.getStatus())) {
            deliveryStep1.setTextColor(Color.parseColor("#6385e6"));
        } else if ("PREPARE".equals(this.paymentDetailModel.getStatus())) {
            deliveryStep2.setTextColor(Color.parseColor("#6385e6"));
        } else if ("BF_DLIV".equals(this.paymentDetailModel.getStatus())) {
            deliveryStep3.setTextColor(Color.parseColor("#6385e6"));
            findViewById(R.id.payment_cancel).setVisibility(8);
            findViewById(R.id.update_order_info).setVisibility(8);
            findViewById(R.id.update_receiver_info).setVisibility(8);
        } else if ("ON_DLIV".equals(this.paymentDetailModel.getStatus())) {
            deliveryStep4.setTextColor(Color.parseColor("#6385e6"));
            findViewById(R.id.payment_cancel).setVisibility(8);
            findViewById(R.id.update_order_info).setVisibility(8);
            findViewById(R.id.update_receiver_info).setVisibility(8);
        } else if ("COMPLETE".equals(this.paymentDetailModel.getStatus())) {
            deliveryStep5.setTextColor(Color.parseColor("#6385e6"));
            findViewById(R.id.payment_cancel).setVisibility(8);
            findViewById(R.id.update_order_info).setVisibility(8);
            findViewById(R.id.update_receiver_info).setVisibility(8);
        }
    }

    /* access modifiers changed from: private */
    public void setPossibleAreaSpinner(ArrayList<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> models) {
        ArrayList<String> si = new ArrayList<>();
        ArrayList<String> gu = new ArrayList<>();
        this.guMap = new HashMap();
        Iterator<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> it = models.iterator();
        while (it.hasNext()) {
            Map<String, ArrayList<DeliveryPossibleAreaDetailModel>> _area = it.next();
            for (String category1 : _area.keySet()) {
                si.add(category1);
                ArrayList<DeliveryPossibleAreaDetailModel> model = _area.get(category1);
                this.guMap.put(category1, model);
                Iterator<DeliveryPossibleAreaDetailModel> it2 = model.iterator();
                while (it2.hasNext()) {
                    DeliveryPossibleAreaDetailModel next = it2.next();
                }
            }
        }
        ArrayAdapter<String> siAdapter = new ArrayAdapter<>(this, R.layout.spinner_textview, si);
        this.siSpinner.setAdapter((SpinnerAdapter) siAdapter);
        siAdapter.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
        Iterator<DeliveryPossibleAreaDetailModel> it3 = this.guMap.get(siAdapter.getItem(0)).iterator();
        while (it3.hasNext()) {
            gu.add(it3.next().getLocalName());
        }
        ArrayAdapter<String> guAdapter = new ArrayAdapter<>(this, R.layout.spinner_textview, gu);
        this.guSpinner.setAdapter((SpinnerAdapter) guAdapter);
        guAdapter.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
    }
}