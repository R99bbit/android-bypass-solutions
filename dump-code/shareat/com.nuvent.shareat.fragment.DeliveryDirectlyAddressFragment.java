package com.nuvent.shareat.fragment;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.support.v7.widget.AppCompatSpinner;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.SpinnerAdapter;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.dialog.ZipCodeDialog;
import com.nuvent.shareat.dialog.ZipCodeDialog.callback;
import com.nuvent.shareat.manager.sns.BaseSnsManager;
import com.nuvent.shareat.model.delivery.DeliveryPossibleAreaDetailModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import net.xenix.android.widget.FontEditTextView;

public class DeliveryDirectlyAddressFragment extends Fragment {
    private ArrayList<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> area = new ArrayList<>();
    /* access modifiers changed from: private */
    public View directlyAddressView;
    /* access modifiers changed from: private */
    public Map<String, ArrayList<DeliveryPossibleAreaDetailModel>> guMap;
    /* access modifiers changed from: private */
    public AppCompatSpinner guSpinner;
    private String method;
    /* access modifiers changed from: private */
    public AppCompatSpinner siSpinner;
    /* access modifiers changed from: private */
    public ZipCodeDialog zipCodeDialog;

    public enum FOCUS_OBJECT {
        RECEIVER_NAME,
        ADDRESS,
        ADDRESS_REST,
        RECEIVER_PHONE,
        ZIP_CODE
    }

    public DeliveryDirectlyAddressFragment() {
    }

    @SuppressLint({"ValidFragment"})
    public DeliveryDirectlyAddressFragment(String method2) {
        this.method = method2;
    }

    @Nullable
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        this.directlyAddressView = inflater.inflate(R.layout.fragment_delivery_directly_address_layout, container, false);
        this.directlyAddressView.findViewById(R.id.search_zip_code).setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                DeliveryDirectlyAddressFragment.this.zipCodeDialog = new ZipCodeDialog(DeliveryDirectlyAddressFragment.this.getContext());
                DeliveryDirectlyAddressFragment.this.zipCodeDialog.setCallback(new callback() {
                    public void callback(final String arg1, final String arg2, final String arg3) {
                        DeliveryDirectlyAddressFragment.this.getActivity().runOnUiThread(new Runnable() {
                            public void run() {
                                ((TextView) DeliveryDirectlyAddressFragment.this.directlyAddressView.findViewById(R.id.zip_code)).setText(arg1);
                                String address = arg2;
                                if (!arg3.isEmpty()) {
                                    address = address + "(" + arg3 + ")";
                                }
                                DeliveryDirectlyAddressFragment.this.directlyAddressView.findViewById(R.id.user_detail_address).clearFocus();
                                DeliveryDirectlyAddressFragment.this.directlyAddressView.findViewById(R.id.user_detail_address).requestFocus();
                                ((TextView) DeliveryDirectlyAddressFragment.this.directlyAddressView.findViewById(R.id.user_detail_address)).setText(address);
                                ((FontEditTextView) DeliveryDirectlyAddressFragment.this.directlyAddressView.findViewById(R.id.user_detail_address)).setSelection(address.length());
                            }
                        });
                    }
                });
                DeliveryDirectlyAddressFragment.this.zipCodeDialog.show();
            }
        });
        this.siSpinner = (AppCompatSpinner) this.directlyAddressView.findViewById(R.id.si);
        this.siSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
                ArrayList<String> gu = new ArrayList<>();
                if (DeliveryDirectlyAddressFragment.this.siSpinner.getSelectedItem() != null) {
                    ArrayAdapter<String> guAdapter = (ArrayAdapter) DeliveryDirectlyAddressFragment.this.guSpinner.getAdapter();
                    guAdapter.clear();
                    Iterator<DeliveryPossibleAreaDetailModel> it = ((ArrayList) DeliveryDirectlyAddressFragment.this.guMap.get((String) DeliveryDirectlyAddressFragment.this.siSpinner.getSelectedItem())).iterator();
                    while (it.hasNext()) {
                        gu.add(it.next().getLocalName());
                    }
                    guAdapter.addAll(gu);
                }
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
        this.guSpinner = (AppCompatSpinner) this.directlyAddressView.findViewById(R.id.gu);
        this.guSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
        if (true == HttpRequest.METHOD_POST.equals(this.method)) {
            setZipCodeVisibility(0);
            this.directlyAddressView.findViewById(R.id.default_address_layout).setVisibility(8);
            ((TextView) this.directlyAddressView.findViewById(R.id.receiver_inquire)).setHint("\ubc30\uc1a1\uc2dc \uc694\uccad\uc0ac\ud56d");
        }
        AppCompatSpinner mobileNumSpinner = (AppCompatSpinner) this.directlyAddressView.findViewById(R.id.mobile_num_direct);
        ArrayList<String> mobileNums = new ArrayList<>();
        mobileNums.add("010");
        mobileNums.add("011");
        mobileNums.add("017");
        mobileNums.add("018");
        mobileNums.add("070");
        mobileNums.add(BaseSnsManager.SNS_LOGIN_TYPE_KAKAO);
        mobileNums.add("031");
        ArrayAdapter<String> adapter = new ArrayAdapter<>(getContext(), R.layout.spinner_textview, mobileNums);
        mobileNumSpinner.setAdapter((SpinnerAdapter) adapter);
        adapter.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
        mobileNumSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
            public void onItemSelected(AdapterView<?> adapterView, View view, int position, long id) {
            }

            public void onNothingSelected(AdapterView<?> adapterView) {
            }
        });
        return this.directlyAddressView;
    }

    public void setOrderRequestLayout(int visibility) {
        if (this.directlyAddressView != null) {
            this.directlyAddressView.findViewById(R.id.order_request_layout).setVisibility(visibility);
        }
    }

    public void setZipCodeVisibility(int visibility) {
        this.directlyAddressView.findViewById(R.id.zip_code_layout).setVisibility(visibility);
    }

    public void setData(ArrayList<Map<String, ArrayList<DeliveryPossibleAreaDetailModel>>> models) {
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
        ArrayAdapter<String> siAdapter = new ArrayAdapter<>(getContext(), R.layout.spinner_textview, si);
        this.siSpinner.setAdapter((SpinnerAdapter) siAdapter);
        siAdapter.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
        Iterator<DeliveryPossibleAreaDetailModel> it3 = this.guMap.get(siAdapter.getItem(0)).iterator();
        while (it3.hasNext()) {
            gu.add(it3.next().getLocalName());
        }
        ArrayAdapter<String> guAdapter = new ArrayAdapter<>(getContext(), R.layout.spinner_textview, gu);
        this.guSpinner.setAdapter((SpinnerAdapter) guAdapter);
        guAdapter.setDropDownViewResource(R.layout.support_simple_spinner_dropdown_item);
    }

    public Map<String, String> getReceiverInfo() {
        Map<String, String> data = new HashMap<>();
        TextView zipCode = (TextView) this.directlyAddressView.findViewById(R.id.zip_code);
        TextView receiverName = (TextView) this.directlyAddressView.findViewById(R.id.receiver_name);
        TextView userDetailAddress = (TextView) this.directlyAddressView.findViewById(R.id.user_detail_address);
        TextView phoneNumber = (TextView) this.directlyAddressView.findViewById(R.id.phone_number);
        TextView requestMessage = (TextView) this.directlyAddressView.findViewById(R.id.receiver_inquire);
        CheckBox defaultAddressCheckBox = (CheckBox) this.directlyAddressView.findViewById(R.id.default_address_checkbox);
        CheckBox useSafePhone = (CheckBox) this.directlyAddressView.findViewById(R.id.use_safe_phone);
        String receiverPhoneNum = ((AppCompatSpinner) this.directlyAddressView.findViewById(R.id.mobile_num_direct)).getSelectedItem().toString() + phoneNumber.getText().toString();
        if (true == phoneNumber.getText().toString().isEmpty()) {
            receiverPhoneNum = "";
        }
        String si = (String) this.siSpinner.getSelectedItem();
        String gu = (String) this.guSpinner.getSelectedItem();
        data.put("receiveName", receiverName.getText().toString());
        if (true == HttpRequest.METHOD_POST.equals(this.method)) {
            data.put("address", "");
        } else {
            data.put("address", si + " " + gu);
        }
        data.put("addressRest", userDetailAddress.getText().toString());
        data.put("receivePhone", receiverPhoneNum);
        data.put("requestMessage", requestMessage.getText().toString());
        data.put("defaultAddress", defaultAddressCheckBox.isChecked() ? "Y" : "N");
        if (zipCode.getVisibility() == 0) {
            data.put("zipCode", zipCode.getText().toString());
        } else {
            data.put("zipCode", "");
        }
        if (useSafePhone.getVisibility() == 0) {
            data.put("useSafePhone", useSafePhone.getText().toString());
        } else {
            data.put("useSafePhone", "");
        }
        return data;
    }

    public void moveFocus(FOCUS_OBJECT focusObject) {
        switch (focusObject) {
            case RECEIVER_NAME:
                this.directlyAddressView.findViewById(R.id.receiver_name).clearFocus();
                this.directlyAddressView.findViewById(R.id.receiver_name).requestFocus();
                return;
            case ADDRESS_REST:
                this.directlyAddressView.findViewById(R.id.user_detail_address).clearFocus();
                this.directlyAddressView.findViewById(R.id.user_detail_address).requestFocus();
                return;
            case RECEIVER_PHONE:
                this.directlyAddressView.findViewById(R.id.phone_number).clearFocus();
                this.directlyAddressView.findViewById(R.id.phone_number).requestFocus();
                return;
            case ZIP_CODE:
                this.directlyAddressView.findViewById(R.id.zip_code).clearFocus();
                this.directlyAddressView.findViewById(R.id.zip_code).requestFocus();
                return;
            default:
                return;
        }
    }
}