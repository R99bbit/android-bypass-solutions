package com.nuvent.shareat.adapter;

import android.app.Activity;
import android.app.AlertDialog.Builder;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.text.TextUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.TextView;
import android.widget.Toast;
import com.google.gson.JsonParser;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.common.CardRegistActivity;
import com.nuvent.shareat.activity.menu.MyPaymentActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.card.CardDeleteApi;
import com.nuvent.shareat.api.card.ChangeCardNameApi;
import com.nuvent.shareat.api.card.ChangeMainCardApi;
import com.nuvent.shareat.dialog.InputCardNameDialog;
import com.nuvent.shareat.dialog.InputCardNameDialog.onOkClickListener;
import com.nuvent.shareat.event.CardUpdateEvent;
import com.nuvent.shareat.model.user.CardModel;
import com.nuvent.shareat.util.GAEvent;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;
import net.xenix.util.ImageDisplay;

public class MyCardAdapter extends BaseAdapter {
    /* access modifiers changed from: private */
    public ArrayList<CardModel> mCardModels = new ArrayList<>();
    /* access modifiers changed from: private */
    public Context mContext;
    private LayoutInflater mLayoutInflater;
    private OnClickCellButton mListener;

    public interface OnClickCellButton {
        void onClickEdit(int i);
    }

    class ViewHolder {
        TextView paymentChangeEdit;
        TextView paymentName;
        TextView paymentNum;
        View paymentSetAdd;
        View paymentSetDel;
        View paymentSetFavorite;
        View paymentSetModify;
        View paymentSetViewDetails;
        ImageView paymentsCardFrame;

        ViewHolder() {
        }
    }

    public MyCardAdapter(Context context) {
        this.mContext = context;
        this.mLayoutInflater = LayoutInflater.from(context);
    }

    public int getCount() {
        return this.mCardModels.size();
    }

    public Object getItem(int position) {
        return this.mCardModels.get(position);
    }

    public long getItemId(int position) {
        return (long) position;
    }

    public View getView(int position, View convertView, ViewGroup parent) {
        ViewHolder viewHolder;
        boolean z;
        boolean z2;
        int i;
        boolean z3;
        boolean z4;
        boolean z5;
        boolean z6;
        boolean z7 = true;
        if (convertView == null) {
            viewHolder = new ViewHolder();
            convertView = this.mLayoutInflater.inflate(R.layout.cell_my_card, null);
            viewHolder.paymentsCardFrame = (ImageView) convertView.findViewById(R.id.payments_set_card_frame);
            viewHolder.paymentSetAdd = convertView.findViewById(R.id.payments_set_add);
            viewHolder.paymentName = (TextView) convertView.findViewById(R.id.payments_set_card_name);
            viewHolder.paymentNum = (TextView) convertView.findViewById(R.id.payments_set_card_num);
            viewHolder.paymentSetFavorite = convertView.findViewById(R.id.my_payment_set_favorite);
            viewHolder.paymentSetModify = convertView.findViewById(R.id.my_payment_set_modify);
            viewHolder.paymentSetDel = convertView.findViewById(R.id.my_payment_set_delete);
            viewHolder.paymentSetViewDetails = convertView.findViewById(R.id.my_payment_view_details);
            convertView.setTag(viewHolder);
        } else {
            viewHolder = (ViewHolder) convertView.getTag();
        }
        final CardModel model = this.mCardModels.get(position);
        viewHolder.paymentNum.setTextColor(model.getCard_id() == null ? this.mContext.getResources().getColor(R.color.payments_setting_empty_text) : this.mContext.getResources().getColor(R.color.payments_setting_num));
        viewHolder.paymentNum.setText((model.getCard_id() == null || !model.getCard_id().equals("00")) ? replaceNum(model.getCard_no()) : "");
        if (model.getCard_id() != null && model.getCard_id().equals("00")) {
            viewHolder.paymentNum.setVisibility(8);
        }
        viewHolder.paymentName.setText(model.getCard_name() == null ? this.mContext.getResources().getString(R.string.MY_CARD_EMPTY_CARD_LABEL) : model.getCard_name());
        View view = viewHolder.paymentSetModify;
        if (model.getCard_id() == null) {
            z = false;
        } else {
            z = true;
        }
        view.setSelected(z);
        View view2 = viewHolder.paymentSetDel;
        if (model.getCard_id() == null) {
            z2 = false;
        } else {
            z2 = true;
        }
        view2.setSelected(z2);
        viewHolder.paymentName.setTextColor(model.getCard_id() == null ? this.mContext.getResources().getColor(R.color.payments_setting_empty_text) : this.mContext.getResources().getColor(R.color.payments_setting_name));
        View view3 = viewHolder.paymentSetAdd;
        if (model.getCard_id() == null) {
            i = 0;
        } else {
            i = 8;
        }
        view3.setVisibility(i);
        View view4 = viewHolder.paymentSetViewDetails;
        if (model.getMain_card() != null) {
            z3 = true;
        } else {
            z3 = false;
        }
        view4.setSelected(z3);
        View view5 = viewHolder.paymentSetFavorite;
        if (model.getMain_card() != null) {
            z4 = true;
        } else {
            z4 = false;
        }
        view5.setEnabled(z4);
        View view6 = viewHolder.paymentSetDel;
        if (model.getMain_card() != null) {
            z5 = true;
        } else {
            z5 = false;
        }
        view6.setEnabled(z5);
        View view7 = viewHolder.paymentSetModify;
        if (model.getMain_card() != null) {
            z6 = true;
        } else {
            z6 = false;
        }
        view7.setEnabled(z6);
        View view8 = viewHolder.paymentSetViewDetails;
        if (model.getMain_card() == null) {
            z7 = false;
        }
        view8.setEnabled(z7);
        viewHolder.paymentSetAdd.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) MyCardAdapter.this.mContext, (int) R.string.payment_setting, (int) R.string.ga_ev_reg, (int) R.string.payment_setting_add_card);
                MyCardAdapter.this.mContext.startActivity(new Intent(MyCardAdapter.this.mContext, CardRegistActivity.class));
            }
        });
        if (model.getCard_id() == null) {
            viewHolder.paymentsCardFrame.setImageResource(R.drawable.my_payment_img);
            viewHolder.paymentsCardFrame.setBackgroundResource(R.drawable.my_payment_img);
            viewHolder.paymentSetFavorite.setBackgroundResource(R.drawable.btn_my_payment_means_favorite_off);
        } else if (model.getCard_id().equals("00")) {
            if (model.getCard_img().equals("-")) {
                viewHolder.paymentsCardFrame.setImageResource(R.drawable.img_card_nu);
            } else {
                viewHolder.paymentsCardFrame.setImageResource(R.drawable.my_payment_img);
            }
            viewHolder.paymentsCardFrame.setBackgroundResource(R.drawable.img_card_nu);
            viewHolder.paymentSetFavorite.setBackgroundResource((model.getMain_card() == null || !model.getMain_card().equals("Y")) ? R.drawable.my_payment_set_favorite_btn : R.drawable.btn_my_payment_means_favorite_p);
        } else {
            ImageDisplay.getInstance().displayImageLoadCard(model.getCard_img(), viewHolder.paymentsCardFrame);
            viewHolder.paymentSetFavorite.setBackgroundResource((model.getMain_card() == null || !model.getMain_card().equals("Y")) ? R.drawable.my_payment_set_favorite_btn : R.drawable.btn_my_payment_means_favorite_p);
        }
        viewHolder.paymentSetDel.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) MyCardAdapter.this.mContext, (int) R.string.payment_setting, (int) R.string.ga_ev_click, (int) R.string.payment_setting_delete_card);
                if (!TextUtils.isEmpty(model.getMain_card()) && model.getMain_card().equals("Y")) {
                    Builder dialog = new Builder(MyCardAdapter.this.mContext);
                    dialog.setMessage(R.string.payment_main_card_del_enable_mag);
                    dialog.setPositiveButton(17039370, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                        }
                    });
                    dialog.show();
                } else if (model.getCard_id().equals("00")) {
                    Builder dialog2 = new Builder(MyCardAdapter.this.mContext);
                    dialog2.setMessage(R.string.payment_main_card_del_enable_cash_card);
                    dialog2.setPositiveButton(17039370, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                        }
                    });
                    dialog2.show();
                } else {
                    String cardName = model.getCard_name() + MyCardAdapter.this.mContext.getString(R.string.payment_main_card_del_req_msg);
                    Builder dialog3 = new Builder(MyCardAdapter.this.mContext);
                    dialog3.setMessage(cardName);
                    dialog3.setPositiveButton(17039370, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            CardDeleteApi request = new CardDeleteApi(MyCardAdapter.this.mContext);
                            request.addParam("card_sno", model.getCard_sno());
                            request.request(new RequestHandler() {
                                public void onResult(Object result) {
                                    if (new JsonParser().parse((String) result).getAsJsonObject().get("result").getAsString().equals("Y")) {
                                        EventBus.getDefault().post(new CardUpdateEvent());
                                    }
                                }
                            });
                            dialog.dismiss();
                        }
                    });
                    dialog3.setNegativeButton(17039360, new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int which) {
                            dialog.dismiss();
                        }
                    });
                    dialog3.show();
                }
            }
        });
        viewHolder.paymentSetViewDetails.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                Intent intent = new Intent(MyCardAdapter.this.mContext, MyPaymentActivity.class);
                intent.putExtra("cardModel", model);
                MyCardAdapter.this.mContext.startActivity(intent);
            }
        });
        viewHolder.paymentSetFavorite.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                String msg = "\"" + model.getCard_name() + "\"" + MyCardAdapter.this.mContext.getString(R.string.payment_main_card_change_req_msg);
                Builder dialog = new Builder(MyCardAdapter.this.mContext);
                dialog.setMessage(msg);
                dialog.setPositiveButton(R.string.ga_ev_change, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        new ChangeMainCardApi(MyCardAdapter.this.mContext, ApiUrl.PAMENT_MAIN_REG + String.format("?card_sno=%1$s", new Object[]{model.getCard_sno()})).request(new RequestHandler() {
                            public void onResult(Object result) {
                                if (new JsonParser().parse((String) result).getAsJsonObject().get("result").getAsString().equals("Y")) {
                                    for (int i = 0; i < MyCardAdapter.this.mCardModels.size(); i++) {
                                        if (model.equals(MyCardAdapter.this.mCardModels.get(i))) {
                                            ((CardModel) MyCardAdapter.this.mCardModels.get(i)).setMain_card("Y");
                                        } else {
                                            ((CardModel) MyCardAdapter.this.mCardModels.get(i)).setMain_card(null);
                                        }
                                    }
                                    MyCardAdapter.this.notifyDataSetChanged();
                                    EventBus.getDefault().post(new CardUpdateEvent());
                                }
                            }
                        });
                        dialog.dismiss();
                    }
                });
                dialog.setNegativeButton(17039360, new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                });
                dialog.show();
            }
        });
        viewHolder.paymentSetModify.setOnClickListener(new OnClickListener() {
            public void onClick(View v) {
                GAEvent.onGaEvent((Activity) (BaseActivity) MyCardAdapter.this.mContext, (int) R.string.payment_setting, (int) R.string.ga_ev_change, (int) R.string.payment_setting_update_card_name);
                InputCardNameDialog dialog = new InputCardNameDialog(MyCardAdapter.this.mContext);
                dialog.setOnOkClickListener(new onOkClickListener() {
                    public void onClick(InputCardNameDialog dialog, String cardName) {
                        if (cardName == null || cardName.equals("")) {
                            MyCardAdapter.this.requestSetCardName(model.getCard_sno(), "");
                        } else if (cardName.length() > 6) {
                            Toast.makeText(MyCardAdapter.this.mContext, R.string.payment_setting_card_rename_length_mag, 0).show();
                            return;
                        } else {
                            MyCardAdapter.this.requestSetCardName(model.getCard_sno(), cardName);
                        }
                        dialog.dismiss();
                    }
                });
                dialog.show();
            }
        });
        return convertView;
    }

    /* access modifiers changed from: private */
    public void requestSetCardName(String cardSno, String cardName) {
        ChangeCardNameApi request = new ChangeCardNameApi(this.mContext);
        request.addParam("card_sno", cardSno);
        request.addParam("card_name", cardName);
        request.request(new RequestHandler() {
            public void onStart() {
                super.onStart();
            }

            public void onFailure(Exception exception) {
                super.onFailure(exception);
            }

            public void onResult(Object result) {
                if (new JsonParser().parse((String) result).getAsJsonObject().get("result").getAsString().equals("Y")) {
                    EventBus.getDefault().post(new CardUpdateEvent());
                }
            }
        });
    }

    public void setData(ArrayList<CardModel> models) {
        this.mCardModels = models;
        notifyDataSetChanged();
    }

    private String replaceNum(String cNo) {
        if (cNo == null || cNo.equals("")) {
            return "\uce74\ub4dc\ubc88\ud638\uc5c6\uc74c";
        }
        String[] nos = cNo.replace("*", "/").split("/");
        return nos[0] + " - **** - **** - " + nos[nos.length - 1];
    }

    public void setOnClickCellButtonListener(OnClickCellButton listener) {
        this.mListener = listener;
    }
}