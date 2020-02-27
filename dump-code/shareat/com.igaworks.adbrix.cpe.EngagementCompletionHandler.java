package com.igaworks.adbrix.cpe;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import com.facebook.appevents.AppEventsConstants;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.model.Engagement;
import com.igaworks.adbrix.model.Segment;
import com.igaworks.adbrix.model.Trigger;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.AbstractCPEImpressionDAO;
import com.igaworks.dao.CounterDAOForAllActivity;
import com.igaworks.dao.CounterDAOForCPEActivity;
import com.igaworks.dao.tracking.TrackingActivityModel;
import com.igaworks.dao.tracking.TrackingActivitySQLiteDB;
import com.igaworks.model.ActivityCounter;
import com.igaworks.model.DuplicationConversionKeyComparator;
import com.igaworks.model.DuplicationConversionKeyModel;
import com.igaworks.util.bolts_task.Capture;
import com.igaworks.util.bolts_task.Continuation;
import com.igaworks.util.bolts_task.Task;
import com.nostra13.universalimageloader.core.download.BaseImageDownloader;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class EngagementCompletionHandler {
    public static void checkAndCompleteEngagement(Context context, String group, String activityName, RequestParameter parameter, ADBrixHttpManager tracerInstance, Calendar restoreTime) {
        int year;
        int month;
        int day;
        int hour;
        Calendar lastCounterCalendar;
        Segment segment;
        Object value;
        Object target;
        try {
            Handler handler = new Handler(Looper.getMainLooper());
            CounterDAOForCPEActivity counterDAOForCPEActivity = CounterDAOForCPEActivity.getDAO(context);
            CounterDAOForAllActivity.getDAO(context).updateItemToAllActivity(group, activityName);
            ArrayList<Integer> conversionCache = parameter.getConversionCache();
            ArrayList<Integer> retainedConversionCache = parameter.getRetainedConversionCache();
            if (conversionCache == null) {
                conversionCache = new ArrayList<>();
            }
            if (retainedConversionCache == null) {
                retainedConversionCache = new ArrayList<>();
            }
            ArrayList<String> AllowDuplicationList = parameter.getAllowDuplicationConversions();
            ArrayList<DuplicationConversionKeyModel> historyList = parameter.getConversionCacheHistory();
            Collections.sort(historyList, new DuplicationConversionKeyComparator());
            if (ADBrixHttpManager.schedule == null || ADBrixHttpManager.schedule.getSchedule() == null || ADBrixHttpManager.schedule.getSchedule().getEngagements() == null) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement schedule is null", 3);
                return;
            }
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement schedule size : " + ADBrixHttpManager.schedule.getSchedule().getEngagements().size(), 3);
            for (Engagement engagement : ADBrixHttpManager.schedule.getSchedule().getEngagements()) {
                String currentGroup = engagement.getTrigger().getGroup();
                String currentActivity = engagement.getTrigger().getActivity();
                boolean allowDuplication = engagement.isAllowDuplication();
                if (!currentGroup.equals(group) || !currentActivity.equals(activityName)) {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement check : current engagement group/activity = " + currentGroup + " / " + currentActivity + " is Not Matched", 3, true);
                } else {
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Item : group = " + currentGroup + ", activity = " + currentActivity + ", allowDuplication: " + allowDuplication, 3, false);
                    if (allowDuplication) {
                        if (retainedConversionCache.contains(Integer.valueOf(engagement.getConversionKey()))) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Already Complete Engagement >> Retained conversion cache exists", 3, false);
                        }
                    } else {
                        if (conversionCache.contains(Integer.valueOf(engagement.getConversionKey()))) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Already Complete Engagement", 3, false);
                        }
                    }
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Check For parent Conversion Key : " + engagement.getParentConversionKey(), 3);
                    if (!(engagement.getParentConversionKey() == -1 || conversionCache == null)) {
                        if (!conversionCache.contains(Integer.valueOf(engagement.getParentConversionKey()))) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Check : Parent Conversion not completed", 3, false);
                        }
                    }
                    if (allowDuplication) {
                        int parentCK = engagement.getParentConversionKey();
                        String targetCKString = new StringBuilder(AbstractCPEImpressionDAO.PARENT_KEY_GROUP).append(parentCK).toString();
                        if (parentCK <= 0 || AllowDuplicationList == null || AllowDuplicationList.size() <= 0 || !AllowDuplicationList.contains(targetCKString)) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Check : Parent Conversion " + parentCK + " > not in AllowDuplicationList", 1, false);
                        } else {
                            ArrayList<DuplicationConversionKeyModel> parentCKHistoryList = new ArrayList<>();
                            Iterator<String> it = AllowDuplicationList.iterator();
                            while (it.hasNext()) {
                                String item = it.next();
                                int i = 0;
                                while (true) {
                                    if (i >= historyList.size()) {
                                        break;
                                    } else if (historyList.get(i).getConversion().equals(item)) {
                                        parentCKHistoryList.add(historyList.get(i));
                                        break;
                                    } else {
                                        i++;
                                    }
                                }
                            }
                            if (parentCKHistoryList.size() > 0) {
                                Collections.sort(parentCKHistoryList, new DuplicationConversionKeyComparator());
                                if (((DuplicationConversionKeyModel) parentCKHistoryList.get(0)).getConversion().equals(targetCKString)) {
                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Check : Parent Conversion " + parentCK + " > in AllowDuplicationList and is the latest ck", 2, false);
                                } else {
                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Check : Parent Conversion " + parentCK + " > in AllowDuplicationList but is not the latest ck", 3, false);
                                }
                            }
                        }
                    }
                    if (engagement.getSegments() != null) {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Segment Check Start", 3);
                        boolean isMatch = true;
                        Iterator<Segment> it2 = engagement.getSegments().iterator();
                        while (true) {
                            if (it2.hasNext()) {
                                segment = it2.next();
                                value = ConditionChecker.getUserValue(context, parameter, 0, new StringBuilder(String.valueOf(engagement.getConversionKey())).toString(), segment.getScheme(), segment.getKey());
                                target = segment.getVal();
                                if (segment.getVal() instanceof Collection) {
                                    if (!(value instanceof String)) {
                                        value = 0;
                                    }
                                    ArrayList arrayList = new ArrayList();
                                    arrayList.add((String) value);
                                    value = arrayList;
                                }
                                if (target == null || value == 0) {
                                    break;
                                }
                                if (!ConditionChecker.isMatch(context, segment.getOp(), target, value, segment.getScheme().equals("app") && segment.getKey().equals("package"))) {
                                    break;
                                }
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Segment check passed : " + segment.getScheme() + " / " + segment.getKey() + " / " + segment.getOp() + " / " + target.toString() + ", UserValue = " + value.toString(), 3);
                            } else {
                                break;
                            }
                        }
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Segment check failed : ", 3, false);
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, segment.getScheme() + " / " + segment.getKey() + " / " + segment.getOp() + " / " + (target == null ? "null" : target.toString()) + ", UserValue = " + (value == 0 ? "null" : value.toString()), 3);
                        isMatch = false;
                        if (!isMatch) {
                            continue;
                        }
                    } else {
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Check : Segment not exist", 3, false);
                    }
                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Trigger Count : " + engagement.getTrigger().getCount(), 3);
                    if (engagement.getTrigger().getCount() > 1) {
                        List<ActivityCounter> counterList = counterDAOForCPEActivity.getActivityCounters(group, activityName);
                        Calendar currentDate = null;
                        if (restoreTime == null) {
                            currentDate = Calendar.getInstance();
                            year = currentDate.get(1);
                            month = currentDate.get(2);
                            day = currentDate.get(5);
                            hour = currentDate.get(11);
                        } else {
                            year = restoreTime.get(1);
                            month = restoreTime.get(2);
                            day = restoreTime.get(5);
                            hour = restoreTime.get(11);
                        }
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Current Date : " + year + "-" + month + "-" + day + " " + hour, 3);
                        if (counterList == null || counterList.size() < 1) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Activity Counter not exist, starting insert row", 3);
                            counterDAOForCPEActivity.insertCounter(year, month, day, hour, group, activityName, restoreTime);
                            if (engagement.getDisplayData().isProgressShow()) {
                                final Engagement engagement2 = engagement;
                                final Context context2 = context;
                                handler.post(new Runnable() {
                                    public void run() {
                                        String progressMsg = Engagement.this.getDisplayData().getProgressMessage().replace("%r", new StringBuilder(String.valueOf(Engagement.this.getTrigger().getCount() - 1)).toString()).replace("%n", AppEventsConstants.EVENT_PARAM_VALUE_YES);
                                        CPEProgressBarHandler.makeToastPopup(context2, Engagement.this.getDisplayData().getProgressTitle(), progressMsg, Engagement.this.getTrigger().getCount(), 1, BaseImageDownloader.DEFAULT_HTTP_CONNECT_TIMEOUT);
                                        CPEProgressBarHandler.setNotification(context2, Engagement.this.getDisplayData().getProgressTitle(), progressMsg);
                                    }
                                });
                            }
                        } else {
                            int cnt = 0;
                            boolean continuous = engagement.getTrigger().isContinuous();
                            long interval = engagement.getTrigger().getIntervalMSec();
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Continuous : " + continuous + ", interval : " + interval, 3);
                            Calendar intervalDate = Calendar.getInstance();
                            if (restoreTime != null) {
                                intervalDate.setTime(new Date());
                            } else {
                                intervalDate.set(1, year);
                                intervalDate.set(2, month);
                                intervalDate.set(5, day);
                                intervalDate.set(11, hour);
                            }
                            intervalDate.setTime(new Date(intervalDate.getTimeInMillis() - engagement.getTrigger().getIntervalMSec()));
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Date For Interval : " + intervalDate.toString(), 3);
                            ActivityCounter lastCounter = counterList.get(0);
                            try {
                                Date lastCounterDate = CounterDAOForCPEActivity.DB_DATE_FORMAT.parse(lastCounter.getUpdateDatetime());
                                lastCounterCalendar = Calendar.getInstance();
                                lastCounterCalendar.setTime(lastCounterDate);
                            } catch (ParseException e) {
                                e.printStackTrace();
                                lastCounterCalendar = Calendar.getInstance();
                                lastCounterCalendar.set(1, lastCounter.getYear());
                                lastCounterCalendar.set(2, lastCounter.getMonth());
                                lastCounterCalendar.set(5, lastCounter.getDay());
                                lastCounterCalendar.set(11, lastCounter.getHour());
                                lastCounterCalendar.set(12, 0);
                                lastCounterCalendar.set(13, 0);
                                lastCounterCalendar.set(14, 0);
                            }
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement Last Count Date : " + lastCounterCalendar.toString(), 3);
                            if (interval > 0 && lastCounterCalendar.after(intervalDate)) {
                                if (restoreTime != null) {
                                    currentDate = restoreTime;
                                }
                                if (!checkResetData(context, currentDate, lastCounterCalendar, engagement.getTrigger())) {
                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement failed by interval", 3, false);
                                    counterDAOForCPEActivity.updateNoCountingDateUpdated(lastCounter, year, month, day, hour, restoreTime);
                                    return;
                                }
                            }
                            Calendar continuousCalendar = Calendar.getInstance();
                            if (restoreTime == null) {
                                continuousCalendar.setTime(new Date());
                            } else {
                                continuousCalendar.set(1, year);
                                continuousCalendar.set(2, month);
                                continuousCalendar.set(5, day);
                                continuousCalendar.set(11, hour);
                            }
                            calculateIntervalDate(engagement.getTrigger(), continuousCalendar);
                            continuousCalendar.setTime(new Date(continuousCalendar.getTimeInMillis() - interval));
                            Calendar currentCalendar = Calendar.getInstance();
                            Iterator<ActivityCounter> it3 = counterList.iterator();
                            while (true) {
                                if (!it3.hasNext()) {
                                    break;
                                }
                                ActivityCounter counter = it3.next();
                                if (interval <= 0 || !continuous) {
                                    cnt += counter.getCounter();
                                } else {
                                    try {
                                        Date currentCalendarDate = CounterDAOForCPEActivity.DB_DATE_FORMAT.parse(counter.getNoCountingUpdateDatetime());
                                        currentCalendar = Calendar.getInstance();
                                        currentCalendar.setTime(currentCalendarDate);
                                    } catch (ParseException e2) {
                                        currentCalendar.set(1, counter.getYearUpdated());
                                        currentCalendar.set(2, counter.getMonthUpdated());
                                        currentCalendar.set(5, counter.getDayUpdated());
                                        currentCalendar.set(11, counter.getHourUpdated());
                                    }
                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement continuous check start : target date = " + continuousCalendar.toString() + "\ncurrent date = " + currentCalendar.toString(), 3);
                                    if (continuousCalendar.after(currentCalendar)) {
                                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement failed by continuous", 3, false);
                                        counterDAOForCPEActivity.removeCounterLessThanDate(counter.getYearUpdated(), counter.getMonthUpdated(), counter.getDayUpdated(), counter.getHourUpdated(), group, activityName);
                                        break;
                                    }
                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement current count : " + counter.getCounter(), 3, false);
                                    cnt += counter.getCounter();
                                    try {
                                        Date continuousCalendarDate = CounterDAOForCPEActivity.DB_DATE_FORMAT.parse(counter.getNoCountingUpdateDatetime());
                                        continuousCalendar = Calendar.getInstance();
                                        continuousCalendar.setTime(continuousCalendarDate);
                                    } catch (ParseException e3) {
                                        continuousCalendar.set(1, counter.getYear());
                                        continuousCalendar.set(2, counter.getMonth());
                                        continuousCalendar.set(5, counter.getDay());
                                        continuousCalendar.set(11, counter.getHour());
                                    }
                                    continuousCalendar.setTime(new Date(continuousCalendar.getTimeInMillis() - interval));
                                }
                            }
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement count check : target Count = " + engagement.getTrigger().getCount() + ", current count = " + cnt, 3);
                            if (year == lastCounterCalendar.get(1) && month == lastCounterCalendar.get(2) && day == lastCounterCalendar.get(5) && hour == lastCounterCalendar.get(11)) {
                                counterDAOForCPEActivity.increment(lastCounter);
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement count increased", 3);
                            } else {
                                counterDAOForCPEActivity.insertCounter(year, month, day, hour, group, activityName);
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement counter row inserted", 3);
                            }
                            int cnt2 = cnt + 1;
                            if (cnt2 >= engagement.getTrigger().getCount()) {
                                handleRewardSchedule(context, engagement, conversionCache, parameter, tracerInstance);
                                counterDAOForCPEActivity.removeCounter(group, activityName);
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement completed", 3, false);
                            } else if (engagement.getDisplayData().isProgressShow()) {
                                final Engagement engagement3 = engagement;
                                final int i2 = cnt2;
                                final Context context3 = context;
                                handler.post(new Runnable() {
                                    public void run() {
                                        String progressMsg = Engagement.this.getDisplayData().getProgressMessage().replace("%r", new StringBuilder(String.valueOf(Engagement.this.getTrigger().getCount() - i2)).toString()).replace("%n", new StringBuilder(String.valueOf(i2)).toString());
                                        CPEProgressBarHandler.makeToastPopup(context3, Engagement.this.getDisplayData().getProgressTitle(), progressMsg, Engagement.this.getTrigger().getCount(), i2, BaseImageDownloader.DEFAULT_HTTP_CONNECT_TIMEOUT);
                                        CPEProgressBarHandler.setNotification(context3, Engagement.this.getDisplayData().getProgressTitle(), progressMsg);
                                    }
                                });
                            }
                        }
                    } else {
                        handleRewardSchedule(context, engagement, conversionCache, parameter, tracerInstance);
                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement completed without count check", 3, false);
                    }
                }
            }
        } catch (Exception e4) {
            Log.e(IgawConstant.QA_TAG, "checkAndCompleteEngagement Exception: " + e4.getMessage());
        }
    }

    private static boolean checkResetData(Context context, Calendar currentCalendar, Calendar lastCounterCalendar, Trigger trigger) {
        if (trigger.getResetType() == null) {
            return true;
        }
        int cMonth = currentCalendar.get(2);
        int cWeek = currentCalendar.get(4);
        int i = currentCalendar.get(5);
        int cHour = currentCalendar.get(11);
        int cMin = currentCalendar.get(12);
        int cSec = currentCalendar.get(13);
        int lMonth = lastCounterCalendar.get(2);
        int lWeek = lastCounterCalendar.get(4);
        int i2 = lastCounterCalendar.get(5);
        int lHour = lastCounterCalendar.get(11);
        int lMin = lastCounterCalendar.get(12);
        int lSec = lastCounterCalendar.get(13);
        if (trigger.getResetType().equals("daily")) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement check reset data RESET_DAILY", 3);
            int cTime = Integer.parseInt(new StringBuilder(String.valueOf(String.format("%02d", new Object[]{Integer.valueOf(cHour)}))).append(String.format("%02d", new Object[]{Integer.valueOf(cMin)})).append(String.format("%02d", new Object[]{Integer.valueOf(cSec)})).toString());
            int lTime = Integer.parseInt(new StringBuilder(String.valueOf(String.format("%02d", new Object[]{Integer.valueOf(lHour)}))).append(String.format("%02d", new Object[]{Integer.valueOf(lMin)})).append(String.format("%02d", new Object[]{Integer.valueOf(lSec)})).toString());
            int rTime = Integer.parseInt(new StringBuilder(String.valueOf(String.format("%02d", new Object[]{Integer.valueOf(trigger.getResetData())}))).append("0000").toString());
            if (cTime < lTime) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Add Current/ResetTime +240000", 3);
                cTime += 240000;
                rTime += 240000;
            }
            IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format("cTime : %d, lTime : %d, rTime : %d", new Object[]{Integer.valueOf(cTime), Integer.valueOf(lTime), Integer.valueOf(rTime)}), 3);
            if (cTime >= rTime && lTime <= rTime) {
                return true;
            }
        } else if (trigger.getResetType().equals("weekly")) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement check reset data RESET_WEEKLY", 3);
            long cTime2 = Long.parseLong(new StringBuilder(String.valueOf(cWeek)).append(String.format("%02d", new Object[]{Integer.valueOf(cHour)})).append(String.format("%02d", new Object[]{Integer.valueOf(cMin)})).append(String.format("%02d", new Object[]{Integer.valueOf(cSec)})).toString());
            long lTime2 = Long.parseLong(new StringBuilder(String.valueOf(lWeek)).append(String.format("%02d", new Object[]{Integer.valueOf(lHour)})).append(String.format("%02d", new Object[]{Integer.valueOf(lMin)})).append(String.format("%02d", new Object[]{Integer.valueOf(lSec)})).toString());
            long rTime2 = Long.parseLong(new StringBuilder(String.valueOf(cWeek)).append("000000").toString());
            if (cTime2 < lTime2) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Add Current/ResetTime +6000000", 3);
                cTime2 += 6000000;
                rTime2 += 6000000;
            }
            IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format("cTime : %d, lTime : %d, rTime : %d", new Object[]{Long.valueOf(cTime2), Long.valueOf(lTime2), Long.valueOf(rTime2)}), 3);
            if (cTime2 >= rTime2 && lTime2 <= rTime2) {
                return true;
            }
        } else if (trigger.getResetType().equals("monthly")) {
            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Engagement check reset data RESET_MONTHLY", 3);
            long cTime3 = Long.parseLong(new StringBuilder(String.valueOf(String.format("%02d", new Object[]{Integer.valueOf(cMonth)}))).append(String.format("%02d", new Object[]{Integer.valueOf(currentCalendar.get(5))})).append(String.format("%02d", new Object[]{Integer.valueOf(cHour)})).append(String.format("%02d", new Object[]{Integer.valueOf(cMin)})).append(String.format("%02d", new Object[]{Integer.valueOf(cSec)})).toString());
            long lTime3 = Long.parseLong(new StringBuilder(String.valueOf(String.format("%02d", new Object[]{Integer.valueOf(lMonth)}))).append(String.format("%02d", new Object[]{Integer.valueOf(lastCounterCalendar.get(5))})).append(String.format("%02d", new Object[]{Integer.valueOf(lHour)})).append(String.format("%02d", new Object[]{Integer.valueOf(lMin)})).append(String.format("%02d", new Object[]{Integer.valueOf(lSec)})).toString());
            long rTime3 = Long.parseLong(new StringBuilder(String.valueOf(cMonth)).append("00000000").toString());
            if (cTime3 < lTime3) {
                IgawLogger.Logging(context, IgawConstant.QA_TAG, "Add Current/ResetTime +1200000000", 3);
                cTime3 += 1200000000;
                rTime3 += 1200000000;
            }
            IgawLogger.Logging(context, IgawConstant.QA_TAG, String.format("cTime : %d, lTime : %d, rTime : %d", new Object[]{Long.valueOf(cTime3), Long.valueOf(lTime3), Long.valueOf(rTime3)}), 3);
            if (cTime3 >= rTime3 && lTime3 <= rTime3) {
                return true;
            }
        }
        return false;
    }

    private static void calculateIntervalDate(Trigger trigger, Calendar targetTime) {
        Calendar c = Calendar.getInstance();
        c.setTime(targetTime.getTime());
        if (trigger.getResetType() == null) {
            targetTime.setTime(new Date(targetTime.getTimeInMillis() - trigger.getIntervalMSec()));
        } else if (trigger.getResetType().equals("daily")) {
            c.set(11, trigger.getResetData());
            c.set(12, 0);
            c.set(13, 0);
            c.set(14, 0);
            if (targetTime.after(c)) {
                targetTime.setTime(c.getTime());
                return;
            }
            c.add(5, -1);
            targetTime.setTime(c.getTime());
        } else if (trigger.getResetType().equals("weekly")) {
            c.set(7, trigger.getResetData());
            c.set(11, 0);
            c.set(12, 0);
            c.set(13, 0);
            c.set(14, 0);
            if (targetTime.after(c)) {
                targetTime.setTime(c.getTime());
                return;
            }
            c.add(4, -1);
            targetTime.setTime(c.getTime());
        } else if (trigger.getResetType().equals("monthly")) {
            c.set(5, trigger.getResetData());
            c.set(11, 0);
            c.set(12, 0);
            c.set(13, 0);
            c.set(14, 0);
            if (targetTime.after(c)) {
                targetTime.setTime(c.getTime());
                return;
            }
            c.add(2, -1);
            targetTime.setTime(c.getTime());
        } else {
            targetTime.setTime(new Date(targetTime.getTimeInMillis() - trigger.getIntervalMSec()));
        }
    }

    private static void handleRewardSchedule(final Context context, Engagement schedule, ArrayList<Integer> arrayList, RequestParameter parameter, ADBrixHttpManager tracerInstance) {
        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > handleRewardSchedule start", 3);
        final ArrayList<Integer> conversionList = new ArrayList<>();
        conversionList.add(Integer.valueOf(schedule.getConversionKey()));
        final Capture<ArrayList<TrackingActivityModel>> activityParam = new Capture<>(null);
        Task onSuccessTask = Task.forResult(null).onSuccessTask(new Continuation<Void, Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> then(Task<Void> task) throws Exception {
                return TrackingActivitySQLiteDB.getInstance(context).getActivityListParam(false, context, "n/a", "n/a", 0);
            }
        }).onSuccessTask(new Continuation<ArrayList<TrackingActivityModel>, Task<ArrayList<TrackingActivityModel>>>() {
            public Task<ArrayList<TrackingActivityModel>> then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                Capture.this.set((ArrayList) task.getResult());
                return TrackingActivitySQLiteDB.getInstance(context).getImpressionData(false, context);
            }
        });
        final ADBrixHttpManager aDBrixHttpManager = tracerInstance;
        final RequestParameter requestParameter = parameter;
        final Context context2 = context;
        onSuccessTask.onSuccess(new Continuation<ArrayList<TrackingActivityModel>, Void>() {
            public Void then(Task<ArrayList<TrackingActivityModel>> task) throws Exception {
                ADBrixHttpManager.this.completeCPECallForADBrix(requestParameter, context2, (ArrayList) activityParam.get(), (ArrayList) task.getResult(), conversionList);
                return null;
            }
        });
    }
}