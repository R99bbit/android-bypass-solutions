package com.nuvent.shareat.manager;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.content.Context;
import android.util.Patterns;
import com.crashlytics.android.Crashlytics;
import com.loplat.placeengine.Plengi;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.model.external.LoplatConfigModel;
import com.nuvent.shareat.model.store.StoreModel;
import com.nuvent.shareat.util.ShareatLogger;
import java.util.Date;
import java.util.regex.Pattern;

public class LoplatManager {
    private static LoplatManager mInstance = null;
    private LoplatConfigModel loplatConfigModel = null;
    private Context mContext = null;
    private Date mFindPartnerTime = null;
    private boolean mInit = false;
    private boolean mIsFindSuccess = false;
    private boolean mNewStart = false;
    private Date mRecentSearchTime = null;
    private boolean mRunningActionGuideActivity = false;
    private StoreModel mSM = null;
    private int mSearchingStatus = -1;
    private int[] mValidPassHours = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};

    public class LOPLAT_CONFIG {
        public static final int BRANCH_INFO_SAVE_PERIOD = 3;
        public static final int DUPLICATE_BYPASS_PERIOD = 3;
        public static final int MOVE_SCAN_PERIOD = 3;
        public static final int SEARCH_FAIL_PERIOD = 5;
        public static final int STAY_SCAN_PERIOD = 3;

        public LOPLAT_CONFIG() {
        }
    }

    public class SEARCHING_STATUS {
        public static final int END = 1;
        public static final int START = 0;
        public static final int UNKNOWN = -1;

        public SEARCHING_STATUS() {
        }
    }

    public LoplatManager(Context context) {
        this.mContext = context;
    }

    public static LoplatManager getInstance(Context context) {
        if (mInstance == null) {
            mInstance = new LoplatManager(context);
        }
        return mInstance;
    }

    public void clearData() {
        this.mSM = null;
        this.mFindPartnerTime = null;
        this.mRecentSearchTime = null;
        this.mIsFindSuccess = false;
    }

    public void setValidPassHours(int[] arrPassHours) {
        this.mValidPassHours = arrPassHours;
    }

    public void setRecentSearchTime(Date recentSearchTime) {
        this.mRecentSearchTime = recentSearchTime;
    }

    public Date getRecentSearchTime() {
        return this.mRecentSearchTime;
    }

    public void setFindSuccess(boolean bFindSuccess) {
        this.mIsFindSuccess = bFindSuccess;
    }

    public boolean getFindSuccess() {
        return this.mIsFindSuccess;
    }

    public void setRunningActionGuideActivity(boolean bRunningActionGuideActivity) {
        this.mRunningActionGuideActivity = bRunningActionGuideActivity;
    }

    public boolean getRunningActionGuideActivity() {
        return this.mRunningActionGuideActivity;
    }

    public int[] getValidPassHours() {
        return this.mValidPassHours;
    }

    public void setFindPartnerTime(Date _findPartnerTime) {
        this.mFindPartnerTime = _findPartnerTime;
    }

    public Date getFindPartnerTime() {
        return this.mFindPartnerTime;
    }

    public void setStoreModel(StoreModel _sm) {
        this.mSM = _sm;
    }

    public StoreModel getStoreModel() {
        return this.mSM;
    }

    public int isLoplatStatus() {
        return Plengi.getInstance(this.mContext).isEngineWorkable();
    }

    public int getCurrentPlaceStatus() {
        return Plengi.getInstance(this.mContext).getCurrentPlaceStatus();
    }

    public boolean initPlaceEngine() {
        int result = Plengi.getInstance(this.mContext).init("nuvent", "nuvent2016", ShareatApp.getInstance().getUserNum());
        boolean bSuccess = false;
        if (result == 1) {
            bSuccess = true;
        } else if (result == 3) {
            ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] FAIL_INTERNET_UNAVAILABLE");
        } else if (result == 4) {
            ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] FAIL_WIFI_SCAN_UNAVAILABLE");
        }
        int moveScanPeriod = 180000;
        int stayScanPeriod = 180000;
        if (this.loplatConfigModel != null) {
            moveScanPeriod = this.loplatConfigModel.getMoveScanPeriod() * 60000;
            stayScanPeriod = this.loplatConfigModel.getStayScanPeriod() * 60000;
        }
        Plengi.getInstance(this.mContext).setScanPeriod(moveScanPeriod, stayScanPeriod);
        this.mInit = bSuccess;
        return bSuccess;
    }

    private String getUniqueUserId(Context context) {
        Account[] accounts;
        Pattern emailPattern = Patterns.EMAIL_ADDRESS;
        for (Account account : AccountManager.get(context).getAccounts()) {
            if (emailPattern.matcher(account.name).matches()) {
                System.out.println("emails: " + (account.type + ", " + account.name));
                if (account.type.equals("com.google")) {
                    return account.name;
                }
            }
        }
        return null;
    }

    public boolean requestLocationInfo() {
        try {
            int result = Plengi.getInstance(this.mContext).refreshPlace();
            if (result == 1) {
                ShareatLogger.writeLog("[Success] requestLocationInfo Success");
                this.mSearchingStatus = 0;
                ShareatApp.getInstance().setStartSearchTime(System.currentTimeMillis());
                return true;
            } else if (result == 3) {
                ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] FAIL_INTERNET_UNAVAILABLE");
                return false;
            } else if (result == 4) {
                ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] FAIL_WIFI_SCAN_UNAVAILABLE");
                return false;
            } else {
                ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] Fail ETC [" + result + "]");
                return false;
            }
        } catch (IllegalStateException e) {
            Crashlytics.getInstance();
            Crashlytics.logException(e);
            return false;
        } catch (Exception e2) {
            Crashlytics.getInstance();
            Crashlytics.logException(e2);
            return false;
        }
    }

    public boolean startPlaceMonitoring() {
        try {
            int result = Plengi.getInstance(this.mContext).start();
            if (result == 1) {
                ShareatLogger.writeLog("[Success] startPlaceMonitoring Success");
                return true;
            } else if (result == 3) {
                ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] FAIL_INTERNET_UNAVAILABLE");
                return false;
            } else if (result == 4) {
                ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] FAIL_WIFI_SCAN_UNAVAILABLE");
                return false;
            } else {
                ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] Fail ETC [" + result + "]");
                return false;
            }
        } catch (IllegalStateException e) {
            Crashlytics.getInstance();
            Crashlytics.logException(e);
            return false;
        } catch (Exception e2) {
            Crashlytics.getInstance();
            Crashlytics.logException(e2);
            return false;
        }
    }

    public void stopPlaceMonitoring() {
        int result = Plengi.getInstance(this.mContext).stop();
        if (result != 1) {
            if (result == 3) {
                ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] FAIL_INTERNET_UNAVAILABLE");
            } else if (result == 4) {
                ShareatLogger.writeLog("[Err:" + new Throwable().getStackTrace()[0].getLineNumber() + "] FAIL_WIFI_SCAN_UNAVAILABLE");
            }
        }
    }

    public void setNewStart(boolean bNewStart) {
        this.mNewStart = bNewStart;
    }

    public boolean getNewStart() {
        return this.mNewStart;
    }

    public void setInitSuccess(boolean bInit) {
        this.mInit = bInit;
    }

    public boolean getInitSuccess() {
        return this.mInit;
    }

    public LoplatConfigModel getLoplatConfigModel() {
        return this.loplatConfigModel;
    }

    public void setLoplatConfigModel(LoplatConfigModel loplatConfigModel2) {
        this.loplatConfigModel = loplatConfigModel2;
    }

    public int getSearchingStatus() {
        return this.mSearchingStatus;
    }

    public void setSearchingStatus(int SearchingStatus) {
        this.mSearchingStatus = SearchingStatus;
    }
}