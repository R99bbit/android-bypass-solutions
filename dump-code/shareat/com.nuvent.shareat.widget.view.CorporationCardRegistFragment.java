package com.nuvent.shareat.widget.view;

import android.app.Activity;
import android.os.Build.VERSION;
import android.os.Bundle;
import android.support.v4.app.Fragment;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.ActionMode;
import android.view.ActionMode.Callback;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.widget.EditText;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.common.CardRegistActivity;
import com.nuvent.shareat.dialog.TermsCheckDialog;
import com.nuvent.shareat.dialog.TermsCheckDialog.DialogClickListener;
import com.nuvent.shareat.util.GAEvent;
import net.xenix.android.widget.FontEditTextView;
import net.xenix.android.widget.FontEditTextView.EditTextListener;

public class CorporationCardRegistFragment extends Fragment implements OnClickListener {
    /* access modifiers changed from: private */
    public static View sView;
    private TextWatcher businessNumWatcher = new TextWatcher() {
        boolean changed;

        public void onTextChanged(CharSequence s, int start, int before, int count) {
        }

        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        }

        public synchronized void afterTextChanged(Editable s) {
            if (s.length() != 0) {
                if (s.charAt(s.length() - 1) == '-') {
                    StringBuilder sb = new StringBuilder(s).deleteCharAt(s.length() - 1);
                    ((EditText) CorporationCardRegistFragment.sView.findViewById(R.id.businessNum)).setText(sb);
                    ((EditText) CorporationCardRegistFragment.sView.findViewById(R.id.businessNum)).setSelection(sb.length());
                } else if (this.changed) {
                    this.changed = false;
                } else {
                    StringBuilder sb2 = new StringBuilder(s.toString().replaceAll("-", ""));
                    int length = sb2.length();
                    if (length > 5) {
                        this.changed = true;
                        sb2.insert(5, "-").insert(3, "-");
                        ((EditText) CorporationCardRegistFragment.sView.findViewById(R.id.businessNum)).setText(sb2);
                        ((EditText) CorporationCardRegistFragment.sView.findViewById(R.id.businessNum)).setSelection(sb2.length());
                    } else if (length > 3) {
                        this.changed = true;
                        sb2.insert(3, "-");
                        ((EditText) CorporationCardRegistFragment.sView.findViewById(R.id.businessNum)).setText(sb2);
                        ((EditText) CorporationCardRegistFragment.sView.findViewById(R.id.businessNum)).setSelection(sb2.length());
                    }
                    if (12 == s.length()) {
                        ((CardRegistActivity) CorporationCardRegistFragment.this.getActivity()).hideKeyboard(CorporationCardRegistFragment.sView.findViewById(R.id.businessNum));
                    }
                    CorporationCardRegistFragment.this.checkData();
                }
            }
        }
    };

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.confirmButton /*2131296504*/:
                onClickConfirm(v);
                return;
            case R.id.monthHint /*2131296870*/:
            case R.id.passwordHint /*2131297002*/:
            case R.id.yearHint /*2131297511*/:
                onClickHint(v);
                return;
            case R.id.termsButton /*2131297392*/:
                onClickTerms(v);
                return;
            default:
                return;
        }
    }

    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        sView = inflater.inflate(R.layout.activity_corporation_card_regist, container, false);
        setTextChangedListener();
        sView.findViewById(R.id.confirmButton).setEnabled(false);
        sView.findViewById(R.id.termsButton).setOnClickListener(this);
        sView.findViewById(R.id.monthHint).setOnClickListener(this);
        sView.findViewById(R.id.yearHint).setOnClickListener(this);
        sView.findViewById(R.id.passwordHint).setOnClickListener(this);
        sView.findViewById(R.id.confirmButton).setOnClickListener(this);
        return sView;
    }

    private void setTextChangedListener() {
        ((EditText) sView.findViewById(R.id.cardNumberField01)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (4 == s.length()) {
                    ((CardRegistActivity) CorporationCardRegistFragment.this.getActivity()).showKeyboard(CorporationCardRegistFragment.sView.findViewById(R.id.cardNumberField02));
                }
                CorporationCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.cardNumberField02)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (4 == s.length()) {
                    ((CardRegistActivity) CorporationCardRegistFragment.this.getActivity()).showKeyboard(CorporationCardRegistFragment.sView.findViewById(R.id.cardNumberField03));
                }
                CorporationCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.cardNumberField03)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (4 == s.length()) {
                    ((CardRegistActivity) CorporationCardRegistFragment.this.getActivity()).showKeyboard(CorporationCardRegistFragment.sView.findViewById(R.id.cardNumberField04));
                }
                CorporationCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.cardNumberField04)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (4 == s.length()) {
                    CorporationCardRegistFragment.sView.findViewById(R.id.monthHint).performClick();
                }
                CorporationCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.monthField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (2 == s.length()) {
                    CorporationCardRegistFragment.sView.findViewById(R.id.yearHint).performClick();
                }
                CorporationCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.yearField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (2 == s.length()) {
                    CorporationCardRegistFragment.sView.findViewById(R.id.passwordHint).performClick();
                }
                CorporationCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.passwordField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (2 == s.length()) {
                    ((CardRegistActivity) CorporationCardRegistFragment.this.getActivity()).showKeyboard(CorporationCardRegistFragment.sView.findViewById(R.id.businessNum));
                }
                CorporationCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.businessNum)).addTextChangedListener(this.businessNumWatcher);
        blockingPasteText();
    }

    /* access modifiers changed from: 0000 */
    public void blockingPasteText() {
        if (VERSION.SDK_INT >= 23) {
            ((FontEditTextView) sView.findViewById(R.id.businessNum)).setCustomInsertionActionModeCallback(new Callback() {
                public boolean onCreateActionMode(ActionMode mode, Menu menu) {
                    return false;
                }

                public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
                    return false;
                }

                public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
                    return false;
                }

                public void onDestroyActionMode(ActionMode mode) {
                }
            });
        } else {
            ((FontEditTextView) sView.findViewById(R.id.businessNum)).setEditTextListener(new EditTextListener() {
                public void onImeBack(FontEditTextView ctrl, String text) {
                }

                public boolean onTextContextMenuItem(int id) {
                    return false;
                }

                public boolean onSuggestionsEnabled() {
                    return false;
                }
            });
        }
    }

    private boolean isTermsCheck() {
        if (sView.findViewById(R.id.termsButton).isSelected()) {
            return true;
        }
        return false;
    }

    /* access modifiers changed from: private */
    public void checkData() {
        boolean isValidData;
        if (((EditText) sView.findViewById(R.id.cardNumberField01)).getText().toString().isEmpty() || 4 > ((EditText) sView.findViewById(R.id.cardNumberField01)).getText().toString().length() || ((EditText) sView.findViewById(R.id.cardNumberField02)).getText().toString().isEmpty() || 4 > ((EditText) sView.findViewById(R.id.cardNumberField02)).getText().toString().length() || ((EditText) sView.findViewById(R.id.cardNumberField03)).getText().toString().isEmpty() || 4 > ((EditText) sView.findViewById(R.id.cardNumberField03)).getText().toString().length() || ((EditText) sView.findViewById(R.id.cardNumberField04)).getText().toString().isEmpty() || 2 > ((EditText) sView.findViewById(R.id.cardNumberField04)).getText().toString().length() || ((EditText) sView.findViewById(R.id.monthField)).getText().toString().isEmpty() || 2 > ((EditText) sView.findViewById(R.id.monthField)).getText().toString().length() || ((EditText) sView.findViewById(R.id.yearField)).getText().toString().isEmpty() || 2 > ((EditText) sView.findViewById(R.id.yearField)).getText().toString().length() || ((EditText) sView.findViewById(R.id.passwordField)).getText().toString().isEmpty() || 2 > ((EditText) sView.findViewById(R.id.passwordField)).getText().toString().length() || ((EditText) sView.findViewById(R.id.businessNum)).getText().toString().isEmpty() || 12 > ((EditText) sView.findViewById(R.id.businessNum)).getText().toString().length() || !isTermsCheck()) {
            isValidData = false;
        } else {
            isValidData = true;
        }
        sView.findViewById(R.id.confirmButton).setEnabled(isValidData);
    }

    public void onClickHint(View view) {
        switch (view.getId()) {
            case R.id.monthHint /*2131296870*/:
                sView.findViewById(R.id.monthHint).setVisibility(8);
                sView.findViewById(R.id.monthField).setVisibility(0);
                sView.findViewById(R.id.monthLabel).setVisibility(0);
                ((CardRegistActivity) getActivity()).showKeyboard(sView.findViewById(R.id.monthField));
                break;
            case R.id.passwordHint /*2131297002*/:
                sView.findViewById(R.id.passwordHint).setVisibility(8);
                sView.findViewById(R.id.passwordField).setVisibility(0);
                sView.findViewById(R.id.passwordLabel).setVisibility(0);
                ((CardRegistActivity) getActivity()).showKeyboard(sView.findViewById(R.id.passwordField));
                break;
            case R.id.yearHint /*2131297511*/:
                sView.findViewById(R.id.yearHint).setVisibility(8);
                sView.findViewById(R.id.yearField).setVisibility(0);
                sView.findViewById(R.id.yearLabel).setVisibility(0);
                ((CardRegistActivity) getActivity()).showKeyboard(sView.findViewById(R.id.yearField));
                break;
        }
        checkData();
    }

    public void onClickTerms(View view) {
        TermsCheckDialog dialog = new TermsCheckDialog(sView.getContext(), view.isSelected());
        dialog.setOnDialogClickListener(new DialogClickListener() {
            public void onAgreed() {
                CorporationCardRegistFragment.sView.findViewById(R.id.termsButton).setSelected(true);
                CorporationCardRegistFragment.this.checkData();
            }

            public void unCheck() {
                CorporationCardRegistFragment.sView.findViewById(R.id.termsButton).setSelected(false);
                CorporationCardRegistFragment.this.checkData();
            }
        });
        dialog.show();
    }

    public void onClickConfirm(View view) {
        GAEvent.onGaEvent((Activity) (CardRegistActivity) getActivity(), (int) R.string.ga_regist_card, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card_confirm);
        ((CardRegistActivity) getActivity()).requestCoporationCardRegistApi(sView);
    }
}