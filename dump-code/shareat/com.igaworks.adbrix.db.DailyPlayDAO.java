package com.igaworks.adbrix.db;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.Editor;
import android.util.Log;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.model.DailyPlay;
import com.igaworks.adbrix.model.RetryCompleteConversion;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.util.bolts_task.Task;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;

public class DailyPlayDAO {
    private static final String DAILYPLAY_SP_NAME = "daily_play_sp";
    private static final String LASTEST_CONVERION_KEY = "LastConversionKey";
    private static final String LAST_CONVERSION_COMPLETE_DATE_KEY = "previous_date";
    private static final String LAST_ON_START_SESSION_DATETIME = "lastOnStartSessionTime";
    private static final String PENDING_CONVERSION = "PendingConversionKey";
    private static final String PLAY_TIME = "RequiredPlayTime";
    private static final String WAITING_TIME = "waiting_time";
    public static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.KOREA);
    private static DailyPlayDAO singleton;
    boolean isChecking;
    int lastConversionKey;

    private DailyPlayDAO() {
        this.isChecking = false;
        this.lastConversionKey = -1;
        this.isChecking = false;
    }

    public static DailyPlayDAO getInstance() {
        if (singleton == null) {
            singleton = new DailyPlayDAO();
        }
        return singleton;
    }

    private SharedPreferences getSharedPreference(Context context) {
        return context.getSharedPreferences(DAILYPLAY_SP_NAME, 0);
    }

    /* access modifiers changed from: private */
    public Editor getEditor(Context context) {
        return getSharedPreference(context).edit();
    }

    public void saveLastConversionDateTime(final Context context) {
        Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
            public void run() {
                Editor edt = DailyPlayDAO.this.getEditor(context);
                edt.putString(DailyPlayDAO.LAST_CONVERSION_COMPLETE_DATE_KEY, DailyPlayDAO.sdf.format(new Date()));
                edt.commit();
            }
        });
    }

    public void setLatestConversionKey(final Context context, final int parentCK) {
        this.lastConversionKey = parentCK;
        Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
            public void run() {
                Editor edt = DailyPlayDAO.this.getEditor(context);
                edt.putInt(DailyPlayDAO.LASTEST_CONVERION_KEY, parentCK);
                edt.commit();
            }
        });
    }

    public int getLatestConversionKey(Context context) {
        if (this.lastConversionKey != -1) {
            return this.lastConversionKey;
        }
        return getSharedPreference(context).getInt(LASTEST_CONVERION_KEY, -1);
    }

    public void setPendingConversionKey(final Context context, final int previous_parentCK) {
        Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
            public void run() {
                Editor edt = DailyPlayDAO.this.getEditor(context);
                edt.putInt(DailyPlayDAO.PENDING_CONVERSION, previous_parentCK);
                edt.commit();
            }
        });
    }

    public int getPendingConversionKey(Context context) {
        return getSharedPreference(context).getInt(PENDING_CONVERSION, -1);
    }

    public void setPlayTime(final Context context, final int playTime) {
        Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
            public void run() {
                Editor edt = DailyPlayDAO.this.getEditor(context);
                edt.putInt(DailyPlayDAO.PLAY_TIME, playTime);
                edt.commit();
            }
        });
    }

    public int getPlayTime(Context context) {
        return getSharedPreference(context).getInt(PLAY_TIME, 2000);
    }

    public void setWaitingTime(final Context context, final int waitingTime) {
        Task.BACKGROUND_EXECUTOR.execute(new Runnable() {
            public void run() {
                Editor edt = DailyPlayDAO.this.getEditor(context);
                edt.putInt("waiting_time", waitingTime);
                edt.commit();
            }
        });
    }

    public int getWaitingTime(Context context) {
        return getSharedPreference(context).getInt("waiting_time", -1);
    }

    /* JADX INFO: finally extract failed */
    public boolean canJoinCampaignToday(Context context) {
        try {
            if (this.isChecking) {
                Log.d(IgawConstant.QA_TAG, "DailyPlay Skip >> Multiple trigger");
                this.isChecking = false;
                return false;
            }
            this.isChecking = true;
            int waiting_time = getWaitingTime(context);
            String lastCoversionDateTime = getSharedPreference(context).getString(LAST_CONVERSION_COMPLETE_DATE_KEY, "");
            if (lastCoversionDateTime.equals("")) {
                int referrerKey = (int) RequestParameter.getATRequestParameter(context).getReferralKey();
                if (referrerKey > 0) {
                    ArrayList<Integer> conversionCacheList = RequestParameter.getATRequestParameter(context).getConversionCache();
                    int conversionCacheListSize = conversionCacheList.size();
                    if (conversionCacheListSize > 0) {
                        List<DailyPlay> DailyPlayStepList = ADBrixHttpManager.schedule.getSchedule().getReEngagement().getDailyPlay();
                        int DailyPlayStepListSize = DailyPlayStepList.size();
                        if (DailyPlayStepListSize > 0) {
                            ArrayList<Integer> campaignKeyList = new ArrayList<>();
                            boolean isContinueLoop = true;
                            int nextConversionKey = referrerKey;
                            while (isContinueLoop) {
                                isContinueLoop = false;
                                int i = 0;
                                while (true) {
                                    if (i >= DailyPlayStepListSize) {
                                        break;
                                    } else if (DailyPlayStepList.get(i).getParentConversionKey() == nextConversionKey) {
                                        nextConversionKey = DailyPlayStepList.get(i).getConversionKey();
                                        campaignKeyList.add(Integer.valueOf(nextConversionKey));
                                        isContinueLoop = true;
                                        break;
                                    } else {
                                        i++;
                                    }
                                }
                            }
                            int campaignKeyListSize = campaignKeyList.size();
                            int recoverLastConversionKey = -1;
                            if (campaignKeyListSize > 0) {
                                for (int i2 = 0; i2 < campaignKeyListSize; i2++) {
                                    int targetParentCoversion = campaignKeyList.get(i2).intValue();
                                    int j = 0;
                                    while (true) {
                                        if (j >= conversionCacheListSize) {
                                            break;
                                        }
                                        int cKey = conversionCacheList.get(j).intValue();
                                        if (targetParentCoversion == cKey) {
                                            recoverLastConversionKey = cKey;
                                            break;
                                        }
                                        j++;
                                    }
                                }
                            }
                            if (recoverLastConversionKey != -1) {
                                Log.d(IgawConstant.QA_TAG, "DailyPlay Recover >> Last conversion Key = " + recoverLastConversionKey);
                                setLatestConversionKey(context, recoverLastConversionKey);
                                this.isChecking = false;
                                return true;
                            }
                            Log.d(IgawConstant.QA_TAG, "DailyPlay Skip >> First day app launches, recoverLastConversionKey is null ");
                            saveLastConversionDateTime(context);
                            this.isChecking = false;
                            return false;
                        }
                        Log.d(IgawConstant.QA_TAG, "DailyPlay Skip >> Campaign Size = " + DailyPlayStepList.size());
                        saveLastConversionDateTime(context);
                        this.isChecking = false;
                        return false;
                    }
                    Log.d(IgawConstant.QA_TAG, "DailyPlay Skip >> First day app launches, empty conversion cache" + referrerKey);
                    saveLastConversionDateTime(context);
                    this.isChecking = false;
                    return false;
                }
                Log.d(IgawConstant.QA_TAG, "DailyPlay Skip >> Referrer: " + referrerKey);
                this.isChecking = false;
                return false;
            }
            if (waiting_time > 0) {
                try {
                    Date nowDate = new Date();
                    Date lastConversionDate = sdf.parse(lastCoversionDateTime);
                    long nowTime = nowDate.getTime();
                    long expectingTime = lastConversionDate.getTime() + ((long) waiting_time);
                    boolean canJoinCampaignNow = nowTime > expectingTime;
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Now: " + nowTime + " > ExpectingTime: " + expectingTime + " >> " + canJoinCampaignNow, 3);
                    if (canJoinCampaignNow) {
                        setWaitingTime(context, -1);
                    }
                    if (!canJoinCampaignNow) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "Skip DailyPlayCP >> Waiting time not expire", 3, false);
                        saveLastConversionDateTime(context);
                    }
                    this.isChecking = false;
                    return canJoinCampaignNow;
                } catch (Exception e1) {
                    Log.e(IgawConstant.QA_TAG, "Error: " + e1.toString());
                }
            }
            Calendar lastTimeJoinCp = Calendar.getInstance();
            Calendar now = Calendar.getInstance();
            lastTimeJoinCp.setTime(sdf.parse(lastCoversionDateTime));
            if (now.get(5) == lastTimeJoinCp.get(5) && now.get(2) == lastTimeJoinCp.get(2) && now.get(1) == lastTimeJoinCp.get(1)) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Skip DailyPlayCP >> Same day", 3, false);
                saveLastConversionDateTime(context);
                this.isChecking = false;
                return false;
            }
            int pending_CK = getPendingConversionKey(context);
            if (pending_CK > 0) {
                if (RequestParameter.getATRequestParameter(context).getConversionCache().contains(Integer.valueOf(pending_CK))) {
                    setPendingConversionKey(context, -1);
                    pending_CK = -1;
                }
                boolean isOnRetry = false;
                Iterator<RetryCompleteConversion> it = ConversionDAOForRetryCompletion.getDAO(context).getRetryConversions().iterator();
                while (true) {
                    if (it.hasNext()) {
                        if (it.next().getConversionKey() == pending_CK) {
                            isOnRetry = true;
                            break;
                        }
                    } else {
                        break;
                    }
                }
                if (isOnRetry) {
                    saveLastConversionDateTime(context);
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "Skip DailyPlayCP >> Pending CK is on-retry ", 3, false);
                    this.isChecking = false;
                    return false;
                }
                setPendingConversionKey(context, -1);
            }
            this.isChecking = false;
            return true;
        } catch (ParseException e) {
            Log.e(IgawConstant.QA_TAG, "DailyPlayDAO >> canJoinCampaignToday Error: " + e.getMessage());
            this.isChecking = false;
            return false;
        } catch (Throwable th) {
            this.isChecking = false;
            throw th;
        }
    }

    public void setLastOnStartSessionDateTime(Context context) {
        Editor edt = getEditor(context);
        edt.putString(LAST_ON_START_SESSION_DATETIME, sdf.format(new Date()));
        edt.commit();
    }

    public String getLastOnStartSessionDateTime(Context context) {
        return getSharedPreference(context).getString(LAST_ON_START_SESSION_DATETIME, "");
    }
}