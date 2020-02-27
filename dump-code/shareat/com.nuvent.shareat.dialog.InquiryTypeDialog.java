package com.nuvent.shareat.dialog;

import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnDismissListener;
import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.ListView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.model.FaqTypeModel;
import com.nuvent.shareat.widget.factory.FaqTypeViewFactory;
import java.util.ArrayList;
import net.xenix.android.adapter.ReferenceAdapter;
import net.xenix.android.adapter.provider.AdapterViewProvider;

public class InquiryTypeDialog extends BaseDialog implements OnDismissListener {
    /* access modifiers changed from: private */
    public ReferenceAdapter<FaqTypeModel> mAdapter;
    private ListView mListView;
    /* access modifiers changed from: private */
    public DialogClickListener mListener;
    private ArrayList<FaqTypeModel> mModels;

    public interface DialogClickListener {
        void onClickType(FaqTypeModel faqTypeModel);

        void onDismiss();
    }

    public InquiryTypeDialog(Context context, ArrayList<FaqTypeModel> models) {
        super(context);
        this.mModels = models;
        init();
    }

    private void init() {
        View view = View.inflate(getContext(), R.layout.dialog_inquiry_type, null);
        this.mListView = (ListView) view.findViewById(R.id.listView);
        this.mAdapter = new ReferenceAdapter<>(new AdapterViewProvider<FaqTypeModel>() {
            public View getView(FaqTypeModel model, int position) {
                return FaqTypeViewFactory.createView(InquiryTypeDialog.this.getContext(), model);
            }

            public void viewWillDisplay(View convertView, FaqTypeModel model) {
            }
        });
        this.mListView.setOnItemClickListener(new OnItemClickListener() {
            public void onItemClick(AdapterView<?> adapterView, View view, int position, long id) {
                InquiryTypeDialog.this.mListener.onClickType((FaqTypeModel) InquiryTypeDialog.this.mAdapter.getItem(position));
                InquiryTypeDialog.this.mAdapter.notifyDataSetChanged();
                InquiryTypeDialog.this.dismiss();
            }
        });
        this.mAdapter.addAll(this.mModels);
        this.mListView.setAdapter(this.mAdapter.getAdapter());
        setContentView(view);
    }

    public void onDismiss(DialogInterface dialog) {
        this.mListener.onDismiss();
    }

    public void setOnDialogClickListener(DialogClickListener listener) {
        this.mListener = listener;
    }
}