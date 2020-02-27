package com.nuvent.shareat.fragment;

import android.annotation.SuppressLint;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v4.app.Fragment;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.delivery.DeliveryShippingAddressDefaultModel;
import io.fabric.sdk.android.services.network.HttpRequest;
import java.util.HashMap;
import java.util.Map;

public class DeliveryDefaultAddressFragment extends Fragment {
    private View defaultAddressView;
    private DeliveryShippingAddressDefaultModel deliveryShippingAddressDefaultModel;
    private String method;

    public DeliveryDefaultAddressFragment() {
    }

    @SuppressLint({"ValidFragment"})
    public DeliveryDefaultAddressFragment(DeliveryShippingAddressDefaultModel model, String method2) {
        this.deliveryShippingAddressDefaultModel = model;
        this.method = method2;
    }

    @Nullable
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        this.defaultAddressView = inflater.inflate(R.layout.fragment_delivery_default_address_layout, container, false);
        if (this.deliveryShippingAddressDefaultModel == null || this.deliveryShippingAddressDefaultModel.getAddress() == null) {
            this.defaultAddressView.findViewById(R.id.empty_layout).setVisibility(0);
            this.defaultAddressView.findViewById(R.id.default_address_layout).setVisibility(8);
        } else {
            setData(this.deliveryShippingAddressDefaultModel);
        }
        return this.defaultAddressView;
    }

    public void setData(DeliveryShippingAddressDefaultModel model) {
        this.deliveryShippingAddressDefaultModel = model;
        TextView fullAddress = (TextView) this.defaultAddressView.findViewById(R.id.receiver_address);
        TextView receiverPhoneNum = (TextView) this.defaultAddressView.findViewById(R.id.receiver_phone_number);
        TextView receiverName = (TextView) this.defaultAddressView.findViewById(R.id.receiver_name);
        String address = "";
        if (model.getAddress() != null) {
            address = address + model.getAddress();
        }
        if (model.getAddressRest() != null) {
            address = address + " " + model.getAddressRest();
        }
        fullAddress.setText(address);
        if (model.getReceivePhone() != null) {
            receiverPhoneNum.setText(model.getReceivePhone());
        }
        if (model.getReceiveName() != null) {
            receiverName.setText(model.getReceiveName());
        }
        if (true == HttpRequest.METHOD_POST.equals(this.method)) {
            ((TextView) this.defaultAddressView.findViewById(R.id.receiver_inquire)).setHint("\ubc30\uc1a1\uc2dc \uc694\uccad\uc0ac\ud56d");
        }
    }

    public Map<String, String> getReceiverInfo() {
        Map<String, String> data = new HashMap<>();
        data.put("receiveName", this.deliveryShippingAddressDefaultModel.getReceiveName());
        data.put("address", this.deliveryShippingAddressDefaultModel.getAddress());
        data.put("addressRest", this.deliveryShippingAddressDefaultModel.getAddressRest());
        data.put("receivePhone", this.deliveryShippingAddressDefaultModel.getReceivePhone());
        data.put("zipCode", this.deliveryShippingAddressDefaultModel.getZipCode());
        data.put("requestMessage", ((TextView) this.defaultAddressView.findViewById(R.id.receiver_inquire)).getText().toString());
        return data;
    }
}