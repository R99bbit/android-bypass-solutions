package com.nuvent.shareat.activity.common;

import android.app.Activity;
import android.content.DialogInterface;
import android.content.DialogInterface.OnClickListener;
import android.graphics.Color;
import android.os.Bundle;
import android.support.design.widget.TabLayout;
import android.support.design.widget.TabLayout.OnTabSelectedListener;
import android.support.design.widget.TabLayout.Tab;
import android.support.design.widget.TabLayout.TabLayoutOnPageChangeListener;
import android.support.v4.app.Fragment;
import android.support.v4.app.FragmentManager;
import android.support.v4.app.FragmentStatePagerAdapter;
import android.support.v4.view.ViewPager;
import android.support.v4.view.ViewPager.OnPageChangeListener;
import android.view.View;
import android.widget.EditText;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.card.CardRegistApi;
import com.nuvent.shareat.event.CardUpdateEvent;
import com.nuvent.shareat.model.card.CardRegistResultModel;
import com.nuvent.shareat.util.GAEvent;
import com.nuvent.shareat.widget.view.CorporationCardRegistFragment;
import com.nuvent.shareat.widget.view.PrivateCardRegistFragment;
import de.greenrobot.event.EventBus;

public class CardRegistActivity extends MainActionBarActivity {
    public static final int GENDER_FEMALE = 2;
    public static final int GENDER_MALE = 1;
    private TabLayout mTabLayout;
    /* access modifiers changed from: private */
    public ViewPager mViewPager;

    public class CardRegistPagerAdapter extends FragmentStatePagerAdapter {
        private int tabCount;

        public CardRegistPagerAdapter(FragmentManager fm, int tabCount2) {
            super(fm);
            this.tabCount = tabCount2;
        }

        public Fragment getItem(int position) {
            switch (position) {
                case 0:
                    return new PrivateCardRegistFragment();
                case 1:
                    return new CorporationCardRegistFragment();
                default:
                    return null;
            }
        }

        public int getCount() {
            return this.tabCount;
        }
    }

    public void onBackPressed() {
        finish(R.anim.scale_up, R.anim.modal_exit_animation);
    }

    public void onClickBack(View view) {
        onBackPressed();
    }

    public void onClickTitle(View view) {
        onBackPressed();
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_card_regist, 2);
        GAEvent.onGAScreenView(this, R.string.ga_regist_card);
        setTitle("\uacb0\uc81c\uc218\ub2e8\ub4f1\ub85d");
        showSubActionbar();
        showFavoriteButton(false);
        this.mTabLayout = (TabLayout) findViewById(R.id.tabLayout);
        this.mTabLayout.addTab(this.mTabLayout.newTab().setText((int) R.string.ga_regist_private_tab));
        this.mTabLayout.addTab(this.mTabLayout.newTab().setText((int) R.string.ga_regist_corporation_tab));
        this.mTabLayout.setTabGravity(0);
        this.mTabLayout.setSelectedTabIndicatorHeight(9);
        this.mTabLayout.setSelectedTabIndicatorColor(Color.parseColor("#6385e6"));
        this.mTabLayout.setTabTextColors(Color.parseColor("#757b8c"), Color.parseColor("#6385e6"));
        this.mViewPager = (ViewPager) findViewById(R.id.cardRegistPager);
        this.mViewPager.setAdapter(new CardRegistPagerAdapter(getSupportFragmentManager(), this.mTabLayout.getTabCount()));
        this.mViewPager.addOnPageChangeListener(new TabLayoutOnPageChangeListener(this.mTabLayout));
        this.mViewPager.addOnPageChangeListener(new OnPageChangeListener() {
            public void onPageScrolled(int position, float positionOffset, int positionOffsetPixels) {
            }

            public void onPageSelected(int position) {
            }

            public void onPageScrollStateChanged(int state) {
            }
        });
        this.mTabLayout.setOnTabSelectedListener(new OnTabSelectedListener() {
            public void onTabSelected(Tab tab) {
                if (tab.getPosition() != CardRegistActivity.this.mViewPager.getCurrentItem()) {
                    CardRegistActivity.this.mViewPager.setCurrentItem(tab.getPosition());
                }
                GAEvent.onGaEvent((Activity) CardRegistActivity.this, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card, tab.getText().toString());
            }

            public void onTabUnselected(Tab tab) {
            }

            public void onTabReselected(Tab tab) {
                if (tab.getPosition() != CardRegistActivity.this.mViewPager.getCurrentItem()) {
                    CardRegistActivity.this.mViewPager.setCurrentItem(tab.getPosition());
                }
            }
        });
    }

    public void requestPrivateCardRegistApi(final int nGenderType, final View view) {
        String cardNo = ((EditText) view.findViewById(R.id.cardNumberField01)).getText().toString() + ((EditText) view.findViewById(R.id.cardNumberField02)).getText().toString() + ((EditText) view.findViewById(R.id.cardNumberField03)).getText().toString() + ((EditText) view.findViewById(R.id.cardNumberField04)).getText().toString();
        String month = ((EditText) view.findViewById(R.id.monthField)).getText().toString();
        String year = ((EditText) view.findViewById(R.id.yearField)).getText().toString();
        String password = ((EditText) view.findViewById(R.id.passwordField)).getText().toString();
        String birth = ((EditText) view.findViewById(R.id.birthField)).getText().toString().replace("-", "");
        String gender = nGenderType == 2 ? "F" : "M";
        CardRegistApi request = new CardRegistApi(this);
        request.addParam("card_gubun", AppEventsConstants.EVENT_PARAM_VALUE_NO);
        request.addParam("card_no", cardNo);
        request.addParam("month", month);
        request.addParam("year", year);
        request.addParam("card_pwd", password);
        request.addParam("birthday", birth);
        request.addParam("gender", gender);
        request.request(new RequestHandler() {
            public void onStart() {
                CardRegistActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                OnClickListener onClickListener;
                CardRegistActivity.this.showCircleDialog(false);
                GAEvent.onGaEvent((Activity) CardRegistActivity.this, (int) R.string.payment_setting, (int) R.string.ga_ev_card_reg, (int) R.string.payment_setting_add_card);
                CardRegistResultModel model = (CardRegistResultModel) result;
                if (model.isOkResponse()) {
                    if (model.getResult().equals("Y")) {
                        GAEvent.onGaEvent((Activity) CardRegistActivity.this, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card_success);
                        onClickListener = new OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                CardRegistActivity.this.showDialog(CardRegistActivity.this.getResources().getString(R.string.payment_main_card_change_ok_msg), new OnClickListener() {
                                    public void onClick(DialogInterface dialog, int which) {
                                        EventBus.getDefault().post(new CardUpdateEvent());
                                        CardRegistActivity.this.onBackPressed();
                                    }
                                });
                            }
                        };
                    } else {
                        GAEvent.onGaEvent((Activity) CardRegistActivity.this, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card_fail);
                        onClickListener = new OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                CardRegistActivity.this.showKeyboard(CardRegistActivity.this.findViewById(R.id.cardNumberField01));
                            }
                        };
                    }
                    CardRegistActivity.this.showDialog(model.registerResultMsg(), onClickListener);
                    return;
                }
                GAEvent.onGaEvent((Activity) CardRegistActivity.this, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card_fail);
                CardRegistActivity.this.showDialog(model.getErrorMessage());
            }

            public void onFailure(Exception exception) {
                CardRegistActivity.this.showCircleDialog(false);
                CardRegistActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        CardRegistActivity.this.requestPrivateCardRegistApi(nGenderType, view);
                    }
                });
            }

            public void onFinish() {
                CardRegistActivity.this.showCircleDialog(false);
            }
        });
    }

    public void requestCoporationCardRegistApi(final View view) {
        String cardNo = ((EditText) view.findViewById(R.id.cardNumberField01)).getText().toString() + ((EditText) view.findViewById(R.id.cardNumberField02)).getText().toString() + ((EditText) view.findViewById(R.id.cardNumberField03)).getText().toString() + ((EditText) view.findViewById(R.id.cardNumberField04)).getText().toString();
        String month = ((EditText) view.findViewById(R.id.monthField)).getText().toString();
        String year = ((EditText) view.findViewById(R.id.yearField)).getText().toString();
        String password = ((EditText) view.findViewById(R.id.passwordField)).getText().toString();
        String businessNum = ((EditText) view.findViewById(R.id.businessNum)).getText().toString().replace("-", "");
        CardRegistApi request = new CardRegistApi(this);
        request.addParam("card_gubun", AppEventsConstants.EVENT_PARAM_VALUE_YES);
        request.addParam("business_number", businessNum);
        request.addParam("card_no", cardNo);
        request.addParam("month", month);
        request.addParam("year", year);
        request.addParam("card_pwd", password);
        request.request(new RequestHandler() {
            public void onStart() {
                CardRegistActivity.this.showCircleDialog(true);
            }

            public void onResult(Object result) {
                OnClickListener onClickListener;
                CardRegistActivity.this.showCircleDialog(false);
                GAEvent.onGaEvent((Activity) CardRegistActivity.this, (int) R.string.payment_setting, (int) R.string.ga_ev_card_reg, (int) R.string.payment_setting_add_card);
                CardRegistResultModel model = (CardRegistResultModel) result;
                if (model.isOkResponse()) {
                    if (model.getResult().equals("Y")) {
                        GAEvent.onGaEvent((Activity) CardRegistActivity.this, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card_success);
                        onClickListener = new OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                CardRegistActivity.this.showDialog(CardRegistActivity.this.getResources().getString(R.string.payment_main_card_change_ok_msg), new OnClickListener() {
                                    public void onClick(DialogInterface dialog, int which) {
                                        EventBus.getDefault().post(new CardUpdateEvent());
                                        CardRegistActivity.this.onBackPressed();
                                    }
                                });
                            }
                        };
                    } else {
                        GAEvent.onGaEvent((Activity) CardRegistActivity.this, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card_fail);
                        onClickListener = new OnClickListener() {
                            public void onClick(DialogInterface dialog, int which) {
                                CardRegistActivity.this.showKeyboard(CardRegistActivity.this.findViewById(R.id.cardNumberField01));
                            }
                        };
                    }
                    CardRegistActivity.this.showDialog(model.registerResultMsg(), onClickListener);
                    return;
                }
                GAEvent.onGaEvent((Activity) CardRegistActivity.this, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card_fail);
                CardRegistActivity.this.showDialog(model.getErrorMessage());
            }

            public void onFailure(Exception exception) {
                CardRegistActivity.this.showCircleDialog(false);
                CardRegistActivity.this.handleException(exception, new Runnable() {
                    public void run() {
                        CardRegistActivity.this.requestCoporationCardRegistApi(view);
                    }
                });
            }

            public void onFinish() {
                CardRegistActivity.this.showCircleDialog(false);
            }
        });
    }
}