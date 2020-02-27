package com.igaworks.core;

import java.util.Locale;

public class IgawConstant {
    public static final int AD_SPACE = 2;
    public static final int ENGAGEMENT = 0;
    public static final int PROMOTION = 1;
    public static final String QA_TAG = "IGAW_QA";
    public String complete;
    public String confirm;
    public String network_error_message;
    public String network_error_title;
    public String process;
    public String retry;

    public IgawConstant() {
        getLocaleMessage();
    }

    private void getLocaleMessage() {
        if (Locale.getDefault().getLanguage().contains("ko")) {
            this.confirm = "\u022e\ufffd\ufffd";
            this.complete = " \ufffd\u03f7\ufffd";
            this.process = "\ufffd\ufffd\ufffd\ufffd\ufffd\u0232   ";
            this.network_error_title = "\ufffd\ufffd\u01ae\ufffd\ufffd\u0169 \ufffd\ufffd\ufffd\ufffd";
            this.network_error_message = "\ufffd\ufffd\u01ae\ufffd\ufffd\u0169 \ufffd\ufffd\ufffd \ufffd\ufffd \ufffd\ufffd\ufffd\ufffd\ufffd\ufffd \ufffd\u07fb\ufffd\ufffd\u03ff\ufffd\ufffd\ufffd\ufffd\u03f4\ufffd. \ufffd\ufffd\ufffd \ufffd\ufffd \ufffd\u067d\ufffd \ufffd\u00f5\ufffd\ufffd\ufffd \ufffd\u05bc\ufffd\ufffd\ufffd.";
            this.retry = "\ufffd\ufffd\u00f5\ufffd";
            return;
        }
        this.confirm = "confirm";
        this.complete = " complete";
        this.process = "Now   ";
        this.network_error_title = "Network Error";
        this.network_error_message = "Network error has occured. Please try to later.";
        this.retry = "Retry";
    }
}