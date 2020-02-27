package com.nuvent.shareat.model.delivery;

import com.nuvent.shareat.model.JsonConvertable;
import java.util.ArrayList;

public class DeliveryShippingAddressResultModel extends JsonConvertable {
    private DeliveryShippingAddressDefaultModel default_address;
    private ArrayList<DeliveryShippingAddressRecentModel> order_address_list = new ArrayList<>();

    public ArrayList<DeliveryShippingAddressRecentModel> getOrder_address_list() {
        return this.order_address_list;
    }

    public void setOrder_address_list(ArrayList<DeliveryShippingAddressRecentModel> order_address_list2) {
        this.order_address_list = order_address_list2;
    }

    public DeliveryShippingAddressDefaultModel getDefault_address() {
        return this.default_address;
    }

    public void setDefault_address(DeliveryShippingAddressDefaultModel default_address2) {
        this.default_address = default_address2;
    }
}