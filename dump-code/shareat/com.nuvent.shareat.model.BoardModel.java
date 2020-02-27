package com.nuvent.shareat.model;

import android.text.Html;
import android.text.Spanned;
import com.igaworks.interfaces.CommonInterface;
import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

public class BoardModel implements Serializable {
    public String ans_board_id;
    public String ans_contents;
    public String ans_levels;
    public String ans_regdate;
    public String ans_title;
    public String board_gubun;
    public String board_id;
    public String chk_ans;
    public String chk_user;
    public String contents;
    public String file_cnt;
    public ArrayList<RowFile> file_list = new ArrayList<>();
    public String gubun;
    public boolean isSelected;
    public String levels;
    public String new_yn;
    public String pop_begindate;
    public String pop_enddate;
    public String pop_height;
    public String pop_width;
    public String popup_yn;
    public String reg_date;
    public String row_num;
    public String title;
    public String up_board_id;

    public class RowFile extends JsonConvertable {
        public String file_id;
        public String file_path;

        public RowFile() {
        }
    }

    public String getNoticeDate() {
        if (this.reg_date == null) {
            return "";
        }
        SimpleDateFormat format = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.getDefault());
        try {
            Date date = format.parse(this.reg_date);
            format.applyPattern("yyyy/MM/dd");
            return format.format(date);
        } catch (ParseException e) {
            e.printStackTrace();
            return this.reg_date;
        }
    }

    public String getInquiryDate() {
        if (this.reg_date == null) {
            return "";
        }
        SimpleDateFormat format = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.getDefault());
        try {
            Date date = format.parse(this.reg_date);
            format.applyPattern("yyyy/MM/dd HH:mm");
            return format.format(date);
        } catch (ParseException e) {
            e.printStackTrace();
            return this.reg_date;
        }
    }

    public String getAnswerDate() {
        if (this.ans_regdate == null) {
            return "";
        }
        SimpleDateFormat format = new SimpleDateFormat(CommonInterface.CREATED_AT_DATE_FORMAT2, Locale.getDefault());
        try {
            Date date = format.parse(this.ans_regdate);
            format.applyPattern("yyyy/MM/dd HH:mm");
            return format.format(date);
        } catch (ParseException e) {
            e.printStackTrace();
            return this.ans_regdate;
        }
    }

    public boolean isNew() {
        return this.new_yn != null && this.new_yn.equals("Y");
    }

    public Spanned getContent() {
        if (this.contents == null) {
            return null;
        }
        return Html.fromHtml(this.contents);
    }

    public Spanned getAnswer() {
        if (this.ans_contents == null) {
            return null;
        }
        return Html.fromHtml(this.ans_contents);
    }

    public boolean hasAnswer() {
        return this.ans_contents != null && this.ans_contents.length() > 0;
    }
}