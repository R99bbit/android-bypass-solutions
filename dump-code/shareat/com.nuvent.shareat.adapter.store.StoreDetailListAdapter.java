package com.nuvent.shareat.adapter.store;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Typeface;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.BaseActivity;
import com.nuvent.shareat.activity.main.ReviewActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.review.ReviewDeleteApi;
import com.nuvent.shareat.api.review.ReviewLikeApi;
import com.nuvent.shareat.event.ReviewCountUpdateEvent;
import com.nuvent.shareat.model.BaseResultModel;
import com.nuvent.shareat.model.store.ReviewLikeResultModel;
import com.nuvent.shareat.model.store.ReviewModel;
import com.nuvent.shareat.model.store.StoreBlogModel;
import com.nuvent.shareat.model.store.StoreInstaModel;
import com.nuvent.shareat.model.store.StoreListModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.factory.ReviewListFactory;
import com.nuvent.shareat.widget.factory.ReviewListFactory.OnClickView;
import de.greenrobot.event.EventBus;
import java.util.ArrayList;

public class StoreDetailListAdapter extends BaseAdapter {
    public static final int LIST_TYPE_BLOG = 3;
    public static final int LIST_TYPE_INSTAGRAM = 2;
    public static final int LIST_TYPE_REVIEW = 1;
    public Context mContext;
    public int mListType = 1;
    /* access modifiers changed from: private */
    public String mPartnerSno;
    private int mSize;
    public ArrayList<? extends StoreListModel> mStoreListModels = new ArrayList<>();
    private Typeface mTypeface;

    public StoreDetailListAdapter(Context context, Typeface typeface) {
        this.mContext = context;
        this.mTypeface = typeface;
    }

    public void setPartnerSno(String partnerSno) {
        this.mPartnerSno = partnerSno;
    }

    public int getCount() {
        int i = 1;
        if (this.mStoreListModels.size() <= 0) {
            return 1;
        }
        switch (this.mListType) {
            case 2:
                int pCount = this.mStoreListModels.size();
                int i2 = pCount / 2;
                if (pCount % 2 == 0) {
                    i = 0;
                }
                return i + i2;
            default:
                return this.mStoreListModels.size();
        }
    }

    public Object getItem(int position) {
        if (this.mStoreListModels.size() <= 0) {
            return Integer.valueOf(0);
        }
        switch (this.mListType) {
            case 2:
                int position2 = Math.min(position * 2, this.mStoreListModels.size() - 1);
                return this.mStoreListModels.subList(position2, Math.min(position2 + 2, this.mStoreListModels.size()));
            default:
                return this.mStoreListModels.get(position);
        }
    }

    public long getItemId(int position) {
        if (this.mStoreListModels.size() > 0) {
            return (long) position;
        }
        return 0;
    }

    public View getView(final int position, View convertView, ViewGroup parent) {
        ReviewListFactory factory = (ReviewListFactory) convertView;
        if (factory == null) {
            factory = new ReviewListFactory(this.mContext);
        }
        if (this.mStoreListModels.size() > 0) {
            switch (this.mListType) {
                case 1:
                    final ReviewModel model = (ReviewModel) this.mStoreListModels.get(position);
                    factory.setData(model, position, this.mTypeface);
                    factory.setOnClickViewListener(new OnClickView() {
                        public void onClickLike(View view) {
                            GAEvent.onGaEvent((Activity) (BaseActivity) StoreDetailListAdapter.this.mContext, (int) R.string.ga_store_detail, (int) R.string.store_detile_action_review_like, (int) R.string.ga_store_detail_review_like);
                            model.reverseLike();
                            StoreDetailListAdapter.this.requestReviewLikeApi(view, model.getFeed_sno(), model.chk_feed, position);
                        }

                        public void onClickDelete() {
                            ((BaseActivity) StoreDetailListAdapter.this.mContext).showConfirmDialog("\ud574\ub2f9 \ub9ac\ubdf0\ub97c \uc0ad\uc81c\ud560\uae4c\uc694?", new Runnable() {
                                public void run() {
                                    StoreDetailListAdapter.this.requestReviewDelete(model.getFeed_sno(), position);
                                }
                            });
                        }

                        public void onClickEdit() {
                            Intent intent = new Intent(StoreDetailListAdapter.this.mContext, ReviewActivity.class);
                            intent.putExtra("partnerSno", StoreDetailListAdapter.this.mPartnerSno);
                            intent.putExtra("model", model);
                            ((BaseActivity) StoreDetailListAdapter.this.mContext).pushActivity(intent);
                        }
                    });
                    break;
                case 2:
                    factory.clearData();
                    if ((position * 2) + 1 >= this.mStoreListModels.size()) {
                        factory.setData((StoreInstaModel) this.mStoreListModels.get(position * 2), null);
                        break;
                    } else {
                        factory.setData((StoreInstaModel) this.mStoreListModels.get(position * 2), (StoreInstaModel) this.mStoreListModels.get((position * 2) + 1));
                        break;
                    }
                case 3:
                    factory.setData((StoreBlogModel) this.mStoreListModels.get(position));
                    break;
            }
        } else {
            factory.setEmpty(this.mSize);
        }
        return factory;
    }

    public void setList(int listType, ArrayList<? extends StoreListModel> models) {
        this.mStoreListModels = models;
        this.mListType = listType;
        notifyDataSetChanged();
    }

    public void setData(ArrayList<? extends StoreListModel> models) {
        this.mStoreListModels = models;
        notifyDataSetChanged();
    }

    public void setSize(int size) {
        this.mSize = size;
    }

    public void requestReviewDelete(final String feedSno, final int position) {
        ReviewDeleteApi request = new ReviewDeleteApi(this.mContext);
        request.addParam("partner_sno", this.mPartnerSno);
        request.addParam("feed_sno", feedSno);
        request.request(new RequestHandler() {
            public void onStart() {
                ((BaseActivity) StoreDetailListAdapter.this.mContext).showCircleDialog(true);
            }

            public void onResult(Object result) {
                ((BaseActivity) StoreDetailListAdapter.this.mContext).showCircleDialog(false);
                if (((BaseResultModel) result).getResult().equals("Y")) {
                    StoreDetailListAdapter.this.mStoreListModels.remove(position);
                    StoreDetailListAdapter.this.notifyDataSetChanged();
                    EventBus.getDefault().post(new ReviewCountUpdateEvent());
                }
            }

            public void onFailure(Exception exception) {
                ((BaseActivity) StoreDetailListAdapter.this.mContext).showCircleDialog(false);
                ((BaseActivity) StoreDetailListAdapter.this.mContext).handleException(exception, new Runnable() {
                    public void run() {
                        StoreDetailListAdapter.this.requestReviewDelete(feedSno, position);
                    }
                });
            }

            public void onFinish() {
                ((BaseActivity) StoreDetailListAdapter.this.mContext).showCircleDialog(false);
            }
        });
    }

    public void requestReviewLikeApi(final View view, String feedSno, String isLike, final int position) {
        ReviewLikeApi request = new ReviewLikeApi(this.mContext);
        request.addParam("partner_sno", this.mPartnerSno);
        request.addParam("feed_sno", feedSno);
        request.addParam("feed_type", isLike);
        request.request(new RequestHandler() {
            public void onResult(Object result) {
                ReviewLikeResultModel model = (ReviewLikeResultModel) result;
                if (!model.getResult().equals("Y")) {
                    view.setSelected(!view.isSelected());
                    StoreDetailListAdapter.this.notifyDataSetChanged();
                    ((ReviewModel) StoreDetailListAdapter.this.mStoreListModels.get(position)).reverseLike();
                    return;
                }
                ((ReviewModel) StoreDetailListAdapter.this.mStoreListModels.get(position)).like_user_text = model.getLike_user_text();
                ((ReviewModel) StoreDetailListAdapter.this.mStoreListModels.get(position)).cnt_like = model.getLike_cnt();
                StoreDetailListAdapter.this.notifyDataSetChanged();
            }

            public void onFailure(Exception exception) {
                view.setSelected(!view.isSelected());
                ((ReviewModel) StoreDetailListAdapter.this.mStoreListModels.get(position)).reverseLike();
                StoreDetailListAdapter.this.notifyDataSetChanged();
            }
        });
    }
}