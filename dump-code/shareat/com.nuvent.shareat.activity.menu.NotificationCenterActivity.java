package com.nuvent.shareat.activity.menu;

import android.annotation.SuppressLint;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.Bitmap.Config;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.renderscript.Allocation;
import android.renderscript.Allocation.MipmapControl;
import android.renderscript.Element;
import android.renderscript.RenderScript;
import android.renderscript.ScriptIntrinsicBlur;
import android.support.v4.content.ContextCompat;
import android.support.v7.widget.LinearLayoutManager;
import android.support.v7.widget.RecyclerView;
import android.support.v7.widget.RecyclerView.Adapter;
import android.support.v7.widget.RecyclerView.ItemDecoration;
import android.support.v7.widget.RecyclerView.LayoutParams;
import android.support.v7.widget.RecyclerView.State;
import android.support.v7.widget.RecyclerView.ViewHolder;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.animation.AnimationUtils;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;
import com.nostra13.universalimageloader.core.assist.FailReason;
import com.nostra13.universalimageloader.core.listener.ImageLoadingListener;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.DeletePushAllApi;
import com.nuvent.shareat.api.common.MyDiscountBenefitApi;
import com.nuvent.shareat.api.common.NotificationCenterApi;
import com.nuvent.shareat.api.common.ReadPushAllApi;
import com.nuvent.shareat.api.common.ReadPushApi;
import com.nuvent.shareat.manager.CustomSchemeManager;
import com.nuvent.shareat.manager.app.AppSettingManager;
import com.nuvent.shareat.model.MyDiscountBenefitModel;
import com.nuvent.shareat.model.NotificationCenterDetailModel;
import com.nuvent.shareat.model.NotificationCenterModel;
import com.nuvent.shareat.receiver.EndlessRecyclerViewScrollListener;
import com.nuvent.shareat.util.BitmapHelper;
import com.nuvent.shareat.util.GAEvent;
import java.util.ArrayList;
import java.util.Iterator;
import net.xenix.util.ImageDisplay;

public class NotificationCenterActivity extends MainActionBarActivity {
    private final int LIST_ITEM_COUNT = 10;
    /* access modifiers changed from: private */
    public Context context;
    private EndlessRecyclerViewScrollListener endlessRecyclerViewScrollListener;
    public int lastPage;
    private LinearLayoutManager layoutManager;
    /* access modifiers changed from: private */
    public MyDiscountBenefitModel myDiscountBenefitModel;
    /* access modifiers changed from: private */
    public NotificationCenterModel notificationCenterModel;
    private RecyclerView recyclerView;
    private RecyclerViewAdapter recyclerViewAdapter;

    public class RecyclerDecoration extends ItemDecoration {
        private Drawable line;
        private final Paint paint = new Paint();

        public RecyclerDecoration(Drawable line2) {
            this.line = line2;
            this.paint.setColor(Color.parseColor("#e8e9ed"));
            this.paint.setStrokeWidth(TypedValue.applyDimension(1, 1.0f, NotificationCenterActivity.this.context.getResources().getDisplayMetrics()));
        }

        public void getItemOffsets(Rect outRect, View view, RecyclerView parent, State state) {
            if (((LayoutParams) view.getLayoutParams()).getViewAdapterPosition() < state.getItemCount()) {
                outRect.set(0, 0, 0, (int) this.paint.getStrokeWidth());
            } else {
                outRect.setEmpty();
            }
        }

        public void onDraw(Canvas c, RecyclerView parent, State state) {
            int offset = (int) (this.paint.getStrokeWidth() / 2.0f);
            for (int i = 0; i < parent.getChildCount(); i++) {
                View view = parent.getChildAt(i);
                if (((LayoutParams) view.getLayoutParams()).getViewAdapterPosition() < state.getItemCount()) {
                    c.drawLine((float) view.getLeft(), (float) (view.getBottom() + offset), (float) view.getRight(), (float) (view.getBottom() + offset), this.paint);
                }
            }
        }
    }

    public class RecyclerViewAdapter extends Adapter<ViewHolder> {
        private static final int TYPE_FOOTER = 2;
        private static final int TYPE_HEADER = 0;
        private static final int TYPE_ITEM = 1;
        /* access modifiers changed from: private */
        public Context context;
        private ArrayList<NotificationCenterDetailModel> model = new ArrayList<>();

        public class RecycleHeaderHolder extends ViewHolder {
            public LinearLayout deleteAllPush;
            public LinearLayout readAllPush;

            public RecycleHeaderHolder(View itemView) {
                super(itemView);
                this.readAllPush = (LinearLayout) itemView.findViewById(R.id.readAllPush);
                this.deleteAllPush = (LinearLayout) itemView.findViewById(R.id.deleteAllPush);
            }
        }

        public class RecyclerHolder extends ViewHolder {
            public TextView message;
            public TextView pastTime;
            public ImageView profileImg;
            public LinearLayout rootCardView;

            public RecyclerHolder(View itemView) {
                super(itemView);
                this.rootCardView = (LinearLayout) itemView.findViewById(R.id.rootCardView);
                this.profileImg = (ImageView) itemView.findViewById(R.id.profileImg);
                this.message = (TextView) itemView.findViewById(R.id.message);
                this.pastTime = (TextView) itemView.findViewById(R.id.pastTime);
            }
        }

        public RecyclerViewAdapter(Context context2, ArrayList<NotificationCenterDetailModel> model2) {
            this.context = context2;
            this.model = model2;
        }

        public void setNotificationCenterModel(ArrayList<NotificationCenterDetailModel> model2) {
            this.model = model2;
        }

        public int getItemCount() {
            if (this.model == null) {
                return 0;
            }
            return this.model.size() + 1;
        }

        public int getItemViewType(int position) {
            if (isPositionHeader(position)) {
                return 0;
            }
            if (isPositionFooter(position)) {
            }
            return 1;
        }

        private boolean isPositionHeader(int position) {
            return position == 0;
        }

        private boolean isPositionFooter(int position) {
            return position == (this.model == null ? 0 : this.model.size() + 1);
        }

        public void onBindViewHolder(ViewHolder holder, int position) {
            if (holder instanceof RecycleHeaderHolder) {
                RecycleHeaderHolder header = (RecycleHeaderHolder) holder;
                header.readAllPush.setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        NotificationCenterActivity.this.requestReadPushAll();
                    }
                });
                header.deleteAllPush.setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        NotificationCenterActivity.this.showConfirmDialog(NotificationCenterActivity.this.getResources().getString(R.string.DELETE_NOTIFICATION_LIST), new Runnable() {
                            public void run() {
                                NotificationCenterActivity.this.requestDeletePushAll();
                            }
                        });
                    }
                });
            } else if (holder instanceof RecyclerHolder) {
                final NotificationCenterDetailModel detailModel = this.model.get(position - 1);
                final RecyclerHolder item = (RecyclerHolder) holder;
                String message = detailModel.getMessage();
                String pastTime = detailModel.getSend_date();
                String feed_sno = detailModel.getFeed_sno();
                final String pushSno = detailModel.getPush_sno();
                if (true == "R".equals(detailModel.getCheck_read())) {
                    item.rootCardView.setBackgroundColor(Color.parseColor("#FFFFFF"));
                } else {
                    item.rootCardView.setBackgroundColor(Color.parseColor("#e8e9ed"));
                }
                item.message.setText(message);
                item.pastTime.setText(pastTime);
                if (detailModel.getProfile() == null || true == detailModel.getProfile().isEmpty()) {
                    ImageDisplay.getInstance().displayImageLoadListRound(detailModel.getProfile(), item.profileImg, NotificationCenterActivity.this.getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX), R.drawable.shareat_push_icon);
                } else {
                    ImageDisplay.getInstance().displayImageLoadListRound(detailModel.getProfile(), item.profileImg, NotificationCenterActivity.this.getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX));
                }
                holder.itemView.setOnClickListener(new OnClickListener() {
                    public void onClick(View v) {
                        String link_url = detailModel.getLink_url();
                        String targetLink = detailModel.getTarget_link();
                        if (true == "N".equals(detailModel.getCheck_read())) {
                            item.rootCardView.setBackgroundColor(Color.parseColor("#FFFFFF"));
                            NotificationCenterActivity.this.requestReadPush(pushSno);
                            detailModel.setCheck_read("R");
                        }
                        if (targetLink != null && !targetLink.isEmpty()) {
                            new CustomSchemeManager();
                            CustomSchemeManager.postSchemeAction(RecyclerViewAdapter.this.context, targetLink);
                        }
                    }
                });
            }
        }

        public ViewHolder onCreateViewHolder(ViewGroup parent, int viewType) {
            if (viewType == 0) {
                return new RecycleHeaderHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.notification_center_cardview_header, parent, false));
            }
            if (viewType != 2 && viewType == 1) {
                return new RecyclerHolder(LayoutInflater.from(parent.getContext()).inflate(R.layout.notification_center_cardview, parent, false));
            }
            return null;
        }
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        GAEvent.onGAScreenView(this, R.string.notification_center);
        this.context = this;
        this.lastPage = 1;
        setContentView(R.layout.activity_notification_list, 2);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle(getResources().getString(R.string.notification_center));
        resetNotificationList();
        this.recyclerView = (RecyclerView) findViewById(R.id.recyclerView);
        this.layoutManager = new LinearLayoutManager(this.context);
        this.recyclerView.setLayoutManager(this.layoutManager);
        this.recyclerView.addItemDecoration(new RecyclerDecoration(ContextCompat.getDrawable(this.context, R.drawable.recycler_view_devide_line)));
        this.recyclerView.setHasFixedSize(true);
        this.endlessRecyclerViewScrollListener = new EndlessRecyclerViewScrollListener(this.layoutManager) {
            public void onLoadMore(int page, int totalItemsCount, RecyclerView view) {
                if (NotificationCenterActivity.this.lastPage == page) {
                    NotificationCenterActivity.this.lastPage = page + 1;
                    NotificationCenterActivity.this.requestNotificationCenterApi(NotificationCenterActivity.this.lastPage);
                }
            }

            public void onScrolled(RecyclerView view, int dx, int dy) {
                super.onScrolled(view, dx, dy);
            }
        };
        this.recyclerView.addOnScrollListener(this.endlessRecyclerViewScrollListener);
        requestMyDiscountBenefitApi();
        requestNotificationCenterApi(this.lastPage);
    }

    private void requestMyDiscountBenefitApi() {
        MyDiscountBenefitApi request = new MyDiscountBenefitApi(this.context);
        request.addGetParam(String.format("?phone_os=A", new Object[0]));
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                if (NotificationCenterActivity.this.myDiscountBenefitModel != null) {
                    NotificationCenterActivity.this.myDiscountBenefitModel = null;
                }
                NotificationCenterActivity.this.myDiscountBenefitModel = (MyDiscountBenefitModel) result;
                NotificationCenterActivity.this.setMyDiscountBenefit();
            }

            public void onFailure(Exception exception) {
                super.onFailure(exception);
            }

            public void onFinish() {
                super.onFinish();
            }
        });
    }

    private void resetNotificationList() {
        ((NotificationManager) getSystemService("notification")).cancelAll();
    }

    /* access modifiers changed from: private */
    public void requestNotificationCenterApi(int page) {
        NotificationCenterApi request = new NotificationCenterApi(this.context);
        request.addGetParam(String.format("?phone_os=A&app_version=%s&page=%d&view_cnt=%d", new Object[]{ShareatApp.getInstance().getAppVersionName(), Integer.valueOf(page), Integer.valueOf(10)}));
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                if (NotificationCenterActivity.this.notificationCenterModel == null) {
                    NotificationCenterActivity.this.notificationCenterModel = (NotificationCenterModel) result;
                } else {
                    NotificationCenterActivity.this.addItem((NotificationCenterModel) result);
                }
                NotificationCenterActivity.this.setRecyclerView();
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
    public void addItem(NotificationCenterModel model) {
        if (model != null) {
            ArrayList<NotificationCenterDetailModel> oldDetailModel = this.notificationCenterModel.getResult_list();
            oldDetailModel.addAll(model.getResult_list());
            this.notificationCenterModel.setResult_list(oldDetailModel);
        }
    }

    /* access modifiers changed from: private */
    public void setMyDiscountBenefit() {
        if (this.myDiscountBenefitModel != null) {
            ImageDisplay.getInstance().displayImageLoad(this.myDiscountBenefitModel.getProfile(), (ImageView) findViewById(R.id.bigProfileImg), R.drawable.profile_user_none, new ImageLoadingListener() {
                public void onLoadingStarted(String imageUri, View view) {
                }

                public void onLoadingFailed(String imageUri, View view, FailReason failReason) {
                }

                public void onLoadingComplete(String imageUri, View view, Bitmap loadedImage) {
                    if (loadedImage.getConfig() == null) {
                        if (VERSION.SDK_INT >= 19) {
                            loadedImage = loadedImage.copy(Config.ARGB_8888, true);
                        } else {
                            loadedImage = Bitmap.createBitmap(loadedImage.getWidth(), loadedImage.getHeight(), Config.ARGB_8888);
                        }
                    }
                    ((ImageView) view).setImageBitmap(BitmapHelper.getBlurEffectBitmap(NotificationCenterActivity.this.context, loadedImage, 10));
                    view.startAnimation(AnimationUtils.loadAnimation(NotificationCenterActivity.this.context, R.anim.fade_in));
                    view.setVisibility(0);
                }

                public void onLoadingCancelled(String imageUri, View view) {
                }
            });
            ImageDisplay.getInstance().displayImageLoadRound(this.myDiscountBenefitModel.getProfile(), (ImageView) findViewById(R.id.profileImg), getResources().getDimensionPixelSize(R.dimen.AVATAR_ROUND_SIZE_15OPX));
            ((TextView) findViewById(R.id.userName)).setText(this.myDiscountBenefitModel.getUser_name());
            ((TextView) findViewById(R.id.benefitTitleText)).setText(this.myDiscountBenefitModel.getBenefitTitleText());
            ((TextView) findViewById(R.id.checkListText)).setText(this.myDiscountBenefitModel.getCheckListText());
            ((TextView) findViewById(R.id.disCount)).setText(this.myDiscountBenefitModel.getDiscount());
        }
    }

    @SuppressLint({"NewApi"})
    private Bitmap blurBitmap(Context context2, Bitmap bitmap, float blurRadius) {
        if (bitmap.getConfig() == null) {
            if (VERSION.SDK_INT >= 19) {
                bitmap.setConfig(Config.ARGB_8888);
            } else {
                bitmap = Bitmap.createBitmap(bitmap.getWidth(), bitmap.getHeight(), Config.ARGB_8888);
            }
        }
        Bitmap outBitmap = Bitmap.createBitmap(bitmap.getWidth(), bitmap.getHeight(), Config.ARGB_8888);
        RenderScript rs = RenderScript.create(context2);
        ScriptIntrinsicBlur blurScript = ScriptIntrinsicBlur.create(rs, Element.U8_4(rs));
        Allocation allIn = Allocation.createFromBitmap(rs, bitmap);
        Allocation allOut = Allocation.createFromBitmap(rs, outBitmap);
        blurScript.setRadius(blurRadius);
        blurScript.setInput(allIn);
        blurScript.forEach(allOut);
        allOut.copyTo(outBitmap);
        bitmap.recycle();
        rs.destroy();
        return outBitmap;
    }

    private Bitmap blur(Context context2, Bitmap sentBitmap, int radius) {
        if (VERSION.SDK_INT <= 16) {
            return null;
        }
        Bitmap bitmap = sentBitmap.copy(sentBitmap.getConfig(), true);
        RenderScript rs = RenderScript.create(context2);
        Allocation input = Allocation.createFromBitmap(rs, sentBitmap, MipmapControl.MIPMAP_NONE, 1);
        Allocation output = Allocation.createTyped(rs, input.getType());
        ScriptIntrinsicBlur script = ScriptIntrinsicBlur.create(rs, Element.U8_4(rs));
        script.setRadius((float) radius);
        script.setInput(input);
        script.forEach(output);
        output.copyTo(bitmap);
        return bitmap;
    }

    /* access modifiers changed from: private */
    public void setRecyclerView() {
        if (this.notificationCenterModel != null) {
            if (this.recyclerViewAdapter == null) {
                this.recyclerViewAdapter = new RecyclerViewAdapter(this.context, this.notificationCenterModel.getResult_list());
                this.recyclerView.setAdapter(this.recyclerViewAdapter);
                return;
            }
            this.recyclerViewAdapter.setNotificationCenterModel(this.notificationCenterModel.getResult_list());
            this.recyclerViewAdapter.notifyDataSetChanged();
        }
    }

    /* access modifiers changed from: private */
    public void requestDeletePushAll() {
        if (this.notificationCenterModel == null || this.notificationCenterModel.getResult_list().size() > 0) {
            DeletePushAllApi request = new DeletePushAllApi(this.context);
            request.addGetParam(String.format("?phone_os=A", new Object[0]));
            request.request(new RequestHandler() {
                public void onResult(Object result) {
                    NotificationCenterActivity.this.readAllBadgeCount();
                    if (NotificationCenterActivity.this.notificationCenterModel != null) {
                        NotificationCenterActivity.this.notificationCenterModel.getResult_list().clear();
                    }
                    NotificationCenterActivity.this.setRecyclerView();
                    NotificationCenterActivity.this.showToast("\uc54c\ub9bc \ub0b4\uc5ed\uc744 \ubaa8\ub450 \uc0ad\uc81c\ud558\uc600\uc2b5\ub2c8\ub2e4");
                }

                public void onFailure(Exception exception) {
                    super.onFailure(exception);
                }

                public void onFinish() {
                    super.onFinish();
                }
            });
        }
    }

    /* access modifiers changed from: private */
    public void requestReadPushAll() {
        if (this.notificationCenterModel == null || this.notificationCenterModel.getResult_list().size() > 0) {
            ReadPushAllApi request = new ReadPushAllApi(this.context);
            request.addGetParam(String.format("?phone_os=A", new Object[0]));
            request.request(new RequestHandler() {
                public void onResult(Object result) {
                    NotificationCenterActivity.this.readAllBadgeCount();
                    NotificationCenterActivity.this.refreshList();
                    NotificationCenterActivity.this.showToast("\uc804\uccb4 \uc77d\uc74c \uc0c1\ud0dc\ub85c \ubcc0\uacbd\ud558\uc600\uc2b5\ub2c8\ub2e4.");
                }

                public void onFailure(Exception exception) {
                    super.onFailure(exception);
                }

                public void onFinish() {
                    super.onFinish();
                }
            });
        }
    }

    /* access modifiers changed from: private */
    public void requestReadPush(String pushSno) {
        ReadPushApi request = new ReadPushApi(this.context);
        request.addGetParam(String.format("?phone_os=A&push_sno=%s", new Object[]{pushSno}));
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                NotificationCenterActivity.this.readBadgeCount();
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
    public void refreshList() {
        Iterator<NotificationCenterDetailModel> it = this.notificationCenterModel.getResult_list().iterator();
        while (it.hasNext()) {
            it.next().setCheck_read("R");
        }
        setRecyclerView();
    }

    /* access modifiers changed from: private */
    public void readAllBadgeCount() {
        Intent badgeIntent = new Intent("android.intent.action.BADGE_COUNT_UPDATE");
        badgeIntent.putExtra("badge_count_package_name", getApplication().getPackageName());
        badgeIntent.putExtra("badge_count_class_name", getApplication().getPackageName() + ".activity.intro.SplashActivity");
        badgeIntent.putExtra("badge_count", 0);
        sendBroadcast(badgeIntent);
        AppSettingManager.getInstance().setNotificationCountint(0);
    }

    /* access modifiers changed from: private */
    public void readBadgeCount() {
        int count = AppSettingManager.getInstance().getNotificationCount() - 1;
        if (count >= 0) {
            Intent badgeIntent = new Intent("android.intent.action.BADGE_COUNT_UPDATE");
            badgeIntent.putExtra("badge_count_package_name", getApplication().getPackageName());
            badgeIntent.putExtra("badge_count_class_name", getApplication().getPackageName() + ".activity.intro.SplashActivity");
            badgeIntent.putExtra("badge_count", count);
            sendBroadcast(badgeIntent);
            AppSettingManager.getInstance().setNotificationCountint(count);
        }
    }
}