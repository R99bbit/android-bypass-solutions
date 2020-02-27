package com.nuvent.shareat.dialog;

import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnDismissListener;
import android.content.Intent;
import android.net.Uri;
import android.os.Build.VERSION;
import android.os.Environment;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.ImageButton;
import com.nuvent.shareat.R;
import java.io.File;

public class PhotoTypeDialog extends BaseDialog implements OnClickListener, OnDismissListener {
    public static final long MAX_SIZE = 1048576;
    public static final String OUTPUT_NAME = "nuvent_profile_photo.jpg";
    public static final int REQUEST_CODE_CAMERA = 1;
    private boolean isHideViewButton;
    private Activity mActivity;
    private ImageButton mCameraButton;
    private DialogClickListener mListener;
    private ImageButton mPickerButton;
    private ImageButton mViewImageButton;

    public interface DialogClickListener {
        void onClickViewer();

        void onDismiss();
    }

    public PhotoTypeDialog(Activity activity, boolean isHideViewButton2) {
        super(activity);
        this.mActivity = activity;
        this.isHideViewButton = isHideViewButton2;
        init(activity);
    }

    private void init(Context context) {
        View view = View.inflate(context, R.layout.dialog_photo_type, null);
        this.mViewImageButton = (ImageButton) view.findViewById(R.id.viewImageButton);
        this.mCameraButton = (ImageButton) view.findViewById(R.id.cameraButton);
        this.mPickerButton = (ImageButton) view.findViewById(R.id.pickerButton);
        this.mViewImageButton.setOnClickListener(this);
        this.mCameraButton.setOnClickListener(this);
        this.mPickerButton.setOnClickListener(this);
        if (this.isHideViewButton) {
            this.mViewImageButton.setVisibility(8);
        }
        setContentView(view);
    }

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.cameraButton /*2131296414*/:
                Intent intent = new Intent("android.media.action.IMAGE_CAPTURE");
                intent.putExtra("output", getCameraOutputUri());
                intent.putExtra("android.intent.extra.sizeLimit", 1048576);
                this.mActivity.startActivityForResult(intent, 1);
                dismiss();
                return;
            case R.id.pickerButton /*2131297098*/:
                Intent photoPickerIntent = new Intent("android.intent.action.PICK");
                photoPickerIntent.setType("image/*");
                photoPickerIntent.setAction("android.intent.action.GET_CONTENT");
                photoPickerIntent.putExtra("android.intent.extra.LOCAL_ONLY", true);
                if (VERSION.SDK_INT < 19) {
                    this.mActivity.startActivityForResult(photoPickerIntent, 102);
                } else {
                    this.mActivity.startActivityForResult(Intent.createChooser(photoPickerIntent, "Complete action using"), 101);
                }
                dismiss();
                return;
            case R.id.viewImageButton /*2131297489*/:
                this.mListener.onClickViewer();
                dismiss();
                return;
            default:
                return;
        }
    }

    public static Uri getCameraOutputUri() {
        return Uri.fromFile(new File(Environment.getExternalStorageDirectory(), OUTPUT_NAME));
    }

    public void onDismiss(DialogInterface dialog) {
        this.mListener.onDismiss();
    }

    public void setOnDialogClickListener(DialogClickListener listener) {
        this.mListener = listener;
    }
}