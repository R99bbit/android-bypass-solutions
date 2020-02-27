package com.igaworks.adbrix.cpe;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.WindowManager.LayoutParams;
import com.igaworks.adbrix.core.ADBrixHttpManager;
import com.igaworks.adbrix.cpe.activitydialog.PromotionActivityDialog;
import com.igaworks.adbrix.cpe.dialog.PromotionDialog;
import com.igaworks.adbrix.interfaces.ADBrixCallbackListener;
import com.igaworks.adbrix.interfaces.PromotionActionListener;
import com.igaworks.adbrix.model.Promotion;
import com.igaworks.adbrix.model.Segment;
import com.igaworks.adbrix.model.Space;
import com.igaworks.adbrix.model.SpaceSegment;
import com.igaworks.core.IgawConstant;
import com.igaworks.core.IgawLogger;
import com.igaworks.core.RequestParameter;
import com.igaworks.dao.NotAvailableCampaignDAO;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class PromotionHandler {
    public static Activity dialogOpenner;
    public static Map<String, Integer> nextCampaigns = new HashMap();
    public static ADBrixCallbackListener onPlayBtnClickListener;
    public static PromotionActionListener promotionActionListener;
    /* access modifiers changed from: private */
    public static Dialog promotionDialog;

    /* JADX WARNING: Code restructure failed: missing block: B:100:0x02ca, code lost:
        r4 = "null";
     */
    /* JADX WARNING: Code restructure failed: missing block: B:101:0x02cd, code lost:
        com.igaworks.core.IgawLogger.Logging(r37, com.igaworks.core.IgawConstant.QA_TAG, r6.append(r4).toString(), 3);
        r18 = false;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:103:0x02e1, code lost:
        r4 = r29.toString();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:104:0x02e6, code lost:
        r4 = r30.toString();
     */
    /* JADX WARNING: Code restructure failed: missing block: B:74:0x01b7, code lost:
        com.igaworks.core.IgawLogger.Logging(r37, com.igaworks.core.IgawConstant.QA_TAG, "ADBrixManager > not available campaign - promotion skipped : " + r22.getDisplay().getTitle(), 3);
     */
    /* JADX WARNING: Code restructure failed: missing block: B:95:0x0276, code lost:
        com.igaworks.core.IgawLogger.Logging(r37, com.igaworks.core.IgawConstant.QA_TAG, "ADBrixManager > Space Segment check failed : ", 3, false);
        r6 = new java.lang.StringBuilder(java.lang.String.valueOf(r25.getScheme())).append(" / ").append(r25.getKey()).append(" / ").append(r25.getOp()).append(" / ");
     */
    /* JADX WARNING: Code restructure failed: missing block: B:96:0x02b8, code lost:
        if (r29 != null) goto L_0x02e1;
     */
    /* JADX WARNING: Code restructure failed: missing block: B:97:0x02ba, code lost:
        r4 = "null";
     */
    /* JADX WARNING: Code restructure failed: missing block: B:98:0x02bd, code lost:
        r6 = r6.append(r4).append(", UserValue = ");
     */
    /* JADX WARNING: Code restructure failed: missing block: B:99:0x02c8, code lost:
        if (r30 != 0) goto L_0x02e6;
     */
    public static void checkAvailablePromotion(Context context, String activityName, RequestParameter parameter) {
        Object valueOf;
        Segment segment;
        Object value;
        Object target;
        Handler handler = new Handler(Looper.getMainLooper());
        try {
            if (ADBrixHttpManager.schedule != null && ADBrixHttpManager.schedule.getSchedule() != null) {
                boolean hasMatchedSpaceKey = false;
                for (Space space : ADBrixHttpManager.schedule.getSchedule().getSpaces()) {
                    if (space.getSpaceKey().equals(activityName)) {
                        hasMatchedSpaceKey = true;
                        List<Integer> campaignKeyList = space.getCampaignList();
                        List<Promotion> promotionList = ADBrixHttpManager.schedule.getSchedule().getPromotions();
                        int primaryCampaignKey = 0;
                        int alternativeCampaignKey = 0;
                        Collection<Integer> notAvailableCampaigns = NotAvailableCampaignDAO.getInstance().getNotAvailableCampaign(context);
                        boolean hasVisibleCampaign = false;
                        ArrayList<Integer> visibleCampaigns = new ArrayList<>();
                        boolean setNextPromotion = false;
                        for (Integer intValue : campaignKeyList) {
                            int campaignKey = intValue.intValue();
                            Iterator<Promotion> it = promotionList.iterator();
                            while (true) {
                                if (!it.hasNext()) {
                                    break;
                                }
                                Promotion promotion = it.next();
                                if (promotion.getCampaignKey() == campaignKey) {
                                    StringBuilder sb = new StringBuilder("ADBrixManager > All Space Segment size =  ");
                                    if (space.getSpaceSegments() == null) {
                                        valueOf = "null";
                                    } else {
                                        valueOf = Integer.valueOf(space.getSpaceSegments().size());
                                    }
                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, sb.append(valueOf).toString(), 3);
                                    if (space.getSpaceSegments() != null) {
                                        List<Segment> currentSegment = null;
                                        Iterator<SpaceSegment> it2 = space.getSpaceSegments().iterator();
                                        while (true) {
                                            if (it2.hasNext()) {
                                                SpaceSegment sSeg = it2.next();
                                                if (sSeg.getCampaignType() == promotion.getCampaignType()) {
                                                    currentSegment = sSeg.getSegments();
                                                    break;
                                                }
                                            } else {
                                                break;
                                            }
                                        }
                                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Space Segment size =  " + (currentSegment == null ? "null" : Integer.valueOf(currentSegment.size())), 3);
                                        if (currentSegment == null || currentSegment.size() <= 0) {
                                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Space Check : Segment not exist", 3, false);
                                        } else {
                                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Space Segment Check Start.", 3);
                                            boolean isMatch = true;
                                            Iterator<Segment> it3 = currentSegment.iterator();
                                            while (true) {
                                                if (it3.hasNext()) {
                                                    Segment segment2 = it3.next();
                                                    Object value2 = ConditionChecker.getUserValue(context, parameter, 2, space.getSpaceKey(), segment2.getScheme(), segment2.getKey());
                                                    Object target2 = segment2.getVal();
                                                    if (segment2.getVal() instanceof Collection) {
                                                        if (!(value2 instanceof String)) {
                                                            value2 = 0;
                                                        }
                                                        ArrayList arrayList = new ArrayList();
                                                        arrayList.add((String) value2);
                                                        value2 = arrayList;
                                                    }
                                                    if (target2 == null || value2 == 0) {
                                                        break;
                                                    }
                                                    if (!ConditionChecker.isMatch(context, segment2.getOp(), target2, value2, segment2.getScheme().equals("app") && segment2.getKey().equals("package"))) {
                                                        break;
                                                    }
                                                    IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Space Segment check passed : " + segment2.getScheme() + " / " + segment2.getKey() + " / " + segment2.getOp() + " / " + (target2 == null ? "null" : target2.toString()) + ", UserValue = " + (value2 == 0 ? "null" : value2.toString()), 3);
                                                } else {
                                                    break;
                                                }
                                            }
                                            if (!isMatch) {
                                                continue;
                                            }
                                        }
                                    }
                                    if (!notAvailableCampaigns.contains(Integer.valueOf(campaignKey))) {
                                        if (promotion.getTargetAppScheme() != null && promotion.getTargetAppScheme().length() > 0 && promotion.isIsFilterAlreadyInstalled() && promotion.getDisplay().getStepReward().size() == 0) {
                                            if (ConditionChecker.checkInstalled(context, promotion.getTargetAppScheme())) {
                                                break;
                                            }
                                        }
                                        visibleCampaigns.add(Integer.valueOf(campaignKey));
                                        if (promotion.getSegments() == null) {
                                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Promotion Check : Segment not exist", 3, false);
                                            break;
                                        }
                                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Promotion Segment Check Start", 3);
                                        boolean isMatch2 = true;
                                        Iterator<Segment> it4 = promotion.getSegments().iterator();
                                        while (true) {
                                            if (it4.hasNext()) {
                                                segment = it4.next();
                                                value = ConditionChecker.getUserValue(context, parameter, 1, new StringBuilder(String.valueOf(promotion.getCampaignKey())).toString(), segment.getScheme(), segment.getKey());
                                                target = segment.getVal();
                                                if (segment.getVal() instanceof Collection) {
                                                    if (!(value instanceof String)) {
                                                        value = 0;
                                                    }
                                                    ArrayList arrayList2 = new ArrayList();
                                                    arrayList2.add((String) value);
                                                    value = arrayList2;
                                                }
                                                if (target == null || value == 0) {
                                                    break;
                                                }
                                                if (!ConditionChecker.isMatch(context, segment.getOp(), target, value, segment.getScheme().equals("app") && segment.getKey().equals("package"))) {
                                                    break;
                                                }
                                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Promotion Segment check passed : " + segment.getScheme() + " / " + segment.getKey() + " / " + segment.getOp() + " / " + target.toString() + ", UserValue = " + value.toString(), 3);
                                            } else {
                                                break;
                                            }
                                        }
                                        IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Promotion Segment check failed : ", 3, false);
                                        IgawLogger.Logging(context, IgawConstant.QA_TAG, segment.getScheme() + " / " + segment.getKey() + " / " + segment.getOp() + " / " + (target == null ? "null" : target.toString()) + ", UserValue = " + (value == 0 ? "null" : value.toString()), 3);
                                        isMatch2 = false;
                                        promotion.setVisible(false);
                                        if (!isMatch2) {
                                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > not matched promotion", 3);
                                            if (nextCampaigns.containsKey(space.getSpaceKey()) && nextCampaigns.get(space.getSpaceKey()).intValue() == promotion.getCampaignKey()) {
                                                nextCampaigns.remove(space.getSpaceKey());
                                            }
                                        } else {
                                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > matched promotion", 3);
                                            hasVisibleCampaign = true;
                                            if (primaryCampaignKey == 0) {
                                                if (alternativeCampaignKey == 0) {
                                                    alternativeCampaignKey = promotion.getCampaignKey();
                                                }
                                                if (nextCampaigns.containsKey(space.getSpaceKey()) && nextCampaigns.get(space.getSpaceKey()).intValue() == promotion.getCampaignKey()) {
                                                    primaryCampaignKey = nextCampaigns.get(space.getSpaceKey()).intValue();
                                                    if (promotion.getCampaignKey() == campaignKeyList.get(campaignKeyList.size() - 1).intValue()) {
                                                        nextCampaigns.remove(space.getSpaceKey());
                                                    }
                                                } else if (!nextCampaigns.containsKey(space.getSpaceKey())) {
                                                    primaryCampaignKey = promotion.getCampaignKey();
                                                }
                                                if (primaryCampaignKey > 0 && (!nextCampaigns.containsKey(space.getSpaceKey()) || (nextCampaigns.containsKey(space.getSpaceKey()) && nextCampaigns.get(space.getSpaceKey()).intValue() == promotion.getCampaignKey()))) {
                                                    setNextPromotion = true;
                                                }
                                            } else if (setNextPromotion) {
                                                nextCampaigns.put(space.getSpaceKey(), Integer.valueOf(promotion.getCampaignKey()));
                                                setNextPromotion = false;
                                            }
                                        }
                                    } else {
                                        break;
                                    }
                                }
                            }
                        }
                        if (nextCampaigns.containsKey(space.getSpaceKey())) {
                            if (!visibleCampaigns.contains(nextCampaigns.get(space.getSpaceKey()))) {
                                nextCampaigns.remove(space.getSpaceKey());
                            }
                        }
                        if (hasVisibleCampaign) {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > has visible promotion", 3);
                            if (primaryCampaignKey == 0 && alternativeCampaignKey > 0) {
                                primaryCampaignKey = alternativeCampaignKey;
                            }
                            if (promotionActionListener != null) {
                                handler.post(new Runnable() {
                                    public void run() {
                                        PromotionHandler.promotionActionListener.onOpenDialog();
                                    }
                                });
                            }
                            showPromotion(context, space, visibleCampaigns, primaryCampaignKey);
                        } else {
                            if (promotionActionListener != null) {
                                handler.post(new Runnable() {
                                    public void run() {
                                        PromotionHandler.promotionActionListener.onNoADAvailable();
                                    }
                                });
                            }
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > Promotion Check : not found available campaign", 3, false);
                        }
                    }
                }
                if (!hasMatchedSpaceKey && promotionActionListener != null) {
                    handler.post(new Runnable() {
                        public void run() {
                            PromotionHandler.promotionActionListener.onNoADAvailable();
                        }
                    });
                }
            } else if (promotionActionListener != null) {
                handler.post(new Runnable() {
                    public void run() {
                        PromotionHandler.promotionActionListener.onNoADAvailable();
                    }
                });
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void showPromotion(final Context context, final Space space, final ArrayList<Integer> visibleCampaigns, final int primaryCampaignKey) throws Exception {
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            public void run() {
                try {
                    if (PromotionHandler.dialogOpenner != null) {
                        IgawLogger.Logging(PromotionHandler.dialogOpenner, IgawConstant.QA_TAG, "ADBrixManager > show promotion dialog", 3);
                        try {
                            if (PromotionHandler.promotionDialog != null && !PromotionHandler.promotionDialog.isShowing()) {
                                PromotionHandler.promotionDialog.dismiss();
                            }
                            PromotionHandler.promotionDialog = new PromotionDialog(PromotionHandler.dialogOpenner, primaryCampaignKey, visibleCampaigns, space.getSpaceKey(), PromotionHandler.onPlayBtnClickListener, PromotionHandler.promotionActionListener);
                            LayoutParams lp = new LayoutParams();
                            lp.copyFrom(PromotionHandler.promotionDialog.getWindow().getAttributes());
                            lp.width = -1;
                            lp.height = -1;
                            PromotionHandler.promotionDialog.getWindow().setAttributes(lp);
                            PromotionHandler.promotionDialog.show();
                        } catch (Exception e) {
                            Log.e(IgawConstant.QA_TAG, "showPromotion Exception: " + e.getMessage());
                        }
                    } else {
                        try {
                            IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > show promotion activity dialog", 3);
                            if (PromotionActivityDialog.isActive) {
                                IgawLogger.Logging(context, IgawConstant.QA_TAG, "ADBrixManager > promotion dialog is already opened", 3);
                                return;
                            }
                            PromotionActivityDialog.onPlayBtnClickListener = PromotionHandler.onPlayBtnClickListener;
                            PromotionActivityDialog.promotionActionListener = PromotionHandler.promotionActionListener;
                            Intent i = new Intent(context, PromotionActivityDialog.class);
                            i.putIntegerArrayListExtra("campaignKeys", visibleCampaigns);
                            i.putExtra("primaryCampaignKey", primaryCampaignKey);
                            i.putExtra("spaceKey", space.getSpaceKey());
                            i.setFlags(268435456);
                            context.startActivity(i);
                        } catch (Exception e2) {
                            Log.e(IgawConstant.QA_TAG, "showPromotionActivity: " + e2.getMessage());
                        }
                    }
                } catch (Exception e3) {
                    e3.printStackTrace();
                    Log.w(IgawConstant.QA_TAG, "showPromotion: " + e3.getMessage());
                }
            }
        });
    }

    public static void closePromotion() {
        new Handler(Looper.getMainLooper()).post(new Runnable() {
            public void run() {
                try {
                    if (PromotionHandler.promotionDialog != null) {
                        PromotionHandler.promotionDialog.dismiss();
                    }
                    if (PromotionActivityDialog.promotionDialog != null) {
                        PromotionActivityDialog.promotionDialog.finish();
                    }
                    PromotionHandler.dialogOpenner = null;
                } catch (Exception e) {
                    Log.w(IgawConstant.QA_TAG, "ClosePromotion: " + e.getMessage());
                }
            }
        });
    }
}