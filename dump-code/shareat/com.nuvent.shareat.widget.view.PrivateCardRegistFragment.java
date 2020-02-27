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
import android.widget.Toast;
import com.facebook.appevents.AppEventsConstants;
import com.nuvent.shareat.R;
import com.nuvent.shareat.activity.common.CardRegistActivity;
import com.nuvent.shareat.dialog.TermsCheckDialog;
import com.nuvent.shareat.dialog.TermsCheckDialog.DialogClickListener;
import com.nuvent.shareat.util.GAEvent;
import net.xenix.android.widget.FontEditTextView;
import net.xenix.android.widget.FontEditTextView.EditTextListener;

public class PrivateCardRegistFragment extends Fragment implements OnClickListener {
    /* access modifiers changed from: private */
    public static View sView;
    private TextWatcher birthWatcher = new TextWatcher() {
        boolean changed;

        public void onTextChanged(CharSequence s, int start, int before, int count) {
        }

        public void beforeTextChanged(CharSequence s, int start, int count, int after) {
        }

        public synchronized void afterTextChanged(Editable s) {
            if (s.length() != 0) {
                if (s.charAt(s.length() - 1) == '-') {
                    StringBuilder sb = new StringBuilder(s).deleteCharAt(s.length() - 1);
                    ((EditText) PrivateCardRegistFragment.sView.findViewById(R.id.birthField)).setText(sb);
                    ((EditText) PrivateCardRegistFragment.sView.findViewById(R.id.birthField)).setSelection(sb.length());
                } else if (this.changed) {
                    this.changed = false;
                } else {
                    StringBuilder sb2 = new StringBuilder(s.toString().replaceAll("-", ""));
                    int length = sb2.length();
                    if (length > 6) {
                        this.changed = true;
                        if (Integer.parseInt(String.valueOf(sb2.substring(4, 6))) > 12) {
                            sb2.insert(4, AppEventsConstants.EVENT_PARAM_VALUE_NO);
                        }
                        sb2.insert(6, "-").insert(4, "-");
                        ((EditText) PrivateCardRegistFragment.sView.findViewById(R.id.birthField)).setText(sb2);
                        ((EditText) PrivateCardRegistFragment.sView.findViewById(R.id.birthField)).setSelection(sb2.length());
                    } else if (length > 4) {
                        this.changed = true;
                        sb2.insert(4, "-");
                        ((EditText) PrivateCardRegistFragment.sView.findViewById(R.id.birthField)).setText(sb2);
                        ((EditText) PrivateCardRegistFragment.sView.findViewById(R.id.birthField)).setSelection(sb2.length());
                    }
                    if (10 == s.length()) {
                        ((CardRegistActivity) PrivateCardRegistFragment.this.getActivity()).hideKeyboard(PrivateCardRegistFragment.sView.findViewById(R.id.birthField));
                    }
                    PrivateCardRegistFragment.this.checkData();
                }
            }
        }
    };

    public void onClick(View v) {
        switch (v.getId()) {
            case R.id.confirmButton /*2131296504*/:
                onClickConfirm(v);
                return;
            case R.id.femaleButton /*2131296652*/:
            case R.id.maleButton /*2131296815*/:
                onClickGender(v);
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
        sView = inflater.inflate(R.layout.activity_private_card_regist_view, container, false);
        setTextChangedListener();
        sView.findViewById(R.id.confirmButton).setEnabled(false);
        sView.findViewById(R.id.termsButton).setOnClickListener(this);
        sView.findViewById(R.id.monthHint).setOnClickListener(this);
        sView.findViewById(R.id.yearHint).setOnClickListener(this);
        sView.findViewById(R.id.passwordHint).setOnClickListener(this);
        sView.findViewById(R.id.maleButton).setOnClickListener(this);
        sView.findViewById(R.id.femaleButton).setOnClickListener(this);
        sView.findViewById(R.id.confirmButton).setOnClickListener(this);
        sView.findViewById(R.id.cardNumberField01).requestFocus();
        sView.findViewById(R.id.cardNumberField01).setFocusable(true);
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
                    ((CardRegistActivity) PrivateCardRegistFragment.this.getActivity()).showKeyboard(PrivateCardRegistFragment.sView.findViewById(R.id.cardNumberField02));
                }
                PrivateCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.cardNumberField02)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (4 == s.length()) {
                    ((CardRegistActivity) PrivateCardRegistFragment.this.getActivity()).showKeyboard(PrivateCardRegistFragment.sView.findViewById(R.id.cardNumberField03));
                }
                PrivateCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.cardNumberField03)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (4 == s.length()) {
                    ((CardRegistActivity) PrivateCardRegistFragment.this.getActivity()).showKeyboard(PrivateCardRegistFragment.sView.findViewById(R.id.cardNumberField04));
                }
                PrivateCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.cardNumberField04)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (4 == s.length()) {
                    PrivateCardRegistFragment.sView.findViewById(R.id.monthHint).performClick();
                }
                PrivateCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.monthField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (2 == s.length()) {
                    PrivateCardRegistFragment.sView.findViewById(R.id.yearHint).performClick();
                }
                PrivateCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.yearField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (2 == s.length()) {
                    PrivateCardRegistFragment.sView.findViewById(R.id.passwordHint).performClick();
                }
                PrivateCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.passwordField)).addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            public void afterTextChanged(Editable s) {
                if (2 == s.length()) {
                    ((CardRegistActivity) PrivateCardRegistFragment.this.getActivity()).showKeyboard(PrivateCardRegistFragment.sView.findViewById(R.id.birthField));
                }
                PrivateCardRegistFragment.this.checkData();
            }
        });
        ((EditText) sView.findViewById(R.id.birthField)).addTextChangedListener(this.birthWatcher);
        blockingPasteText();
    }

    /* access modifiers changed from: 0000 */
    public void blockingPasteText() {
        if (VERSION.SDK_INT >= 23) {
            ((FontEditTextView) sView.findViewById(R.id.birthField)).setCustomInsertionActionModeCallback(new Callback() {
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
            ((FontEditTextView) sView.findViewById(R.id.birthField)).setEditTextListener(new EditTextListener() {
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

    /* access modifiers changed from: private */
    public void checkData() {
        boolean isValidData;
        if (((EditText) sView.findViewById(R.id.cardNumberField01)).getText().toString().isEmpty() || 4 > ((EditText) sView.findViewById(R.id.cardNumberField01)).getText().toString().length() || ((EditText) sView.findViewById(R.id.cardNumberField02)).getText().toString().isEmpty() || 4 > ((EditText) sView.findViewById(R.id.cardNumberField02)).getText().toString().length() || ((EditText) sView.findViewById(R.id.cardNumberField03)).getText().toString().isEmpty() || 4 > ((EditText) sView.findViewById(R.id.cardNumberField03)).getText().toString().length() || ((EditText) sView.findViewById(R.id.cardNumberField04)).getText().toString().isEmpty() || 2 > ((EditText) sView.findViewById(R.id.cardNumberField04)).getText().toString().length() || ((EditText) sView.findViewById(R.id.monthField)).getText().toString().isEmpty() || 2 > ((EditText) sView.findViewById(R.id.monthField)).getText().toString().length() || ((EditText) sView.findViewById(R.id.yearField)).getText().toString().isEmpty() || 2 > ((EditText) sView.findViewById(R.id.yearField)).getText().toString().length() || ((EditText) sView.findViewById(R.id.passwordField)).getText().toString().isEmpty() || 2 > ((EditText) sView.findViewById(R.id.passwordField)).getText().toString().length() || ((EditText) sView.findViewById(R.id.birthField)).getText().toString().isEmpty() || 10 > ((EditText) sView.findViewById(R.id.birthField)).getText().toString().length() || !isTermsCheck()) {
            isValidData = false;
        } else {
            isValidData = true;
        }
        sView.findViewById(R.id.confirmButton).setEnabled(isValidData);
    }

    public void onClickGender(View view) {
        sView.findViewById(R.id.maleButton).setSelected(false);
        sView.findViewById(R.id.femaleButton).setSelected(false);
        sView.findViewById(view.getId()).setSelected(true);
        ((CardRegistActivity) getActivity()).hideKeyboard(sView.findViewById(R.id.birthField));
        checkData();
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
                PrivateCardRegistFragment.sView.findViewById(R.id.termsButton).setSelected(true);
                PrivateCardRegistFragment.this.checkData();
            }

            public void unCheck() {
                PrivateCardRegistFragment.sView.findViewById(R.id.termsButton).setSelected(false);
                PrivateCardRegistFragment.this.checkData();
            }
        });
        dialog.show();
    }

    private boolean isTermsCheck() {
        if (sView.findViewById(R.id.termsButton).isSelected()) {
            return true;
        }
        return false;
    }

    public void onClickConfirm(View view) {
        GAEvent.onGaEvent((Activity) (CardRegistActivity) getActivity(), (int) R.string.ga_regist_card, (int) R.string.ga_regist_card, (int) R.string.ga_regist_card_confirm);
        if (-1 == getGender()) {
            Toast.makeText(sView.getContext(), "\uc131\ubcc4\uc744 \uc120\ud0dd\ud574 \uc8fc\uc138\uc694.", 0).show();
        } else {
            ((CardRegistActivity) getActivity()).requestPrivateCardRegistApi(getGender(), sView);
        }
    }

    private int getGender() {
        if (!sView.findViewById(R.id.maleButton).isSelected() && !sView.findViewById(R.id.femaleButton).isSelected()) {
            return -1;
        }
        if (sView.findViewById(R.id.maleButton).isSelected()) {
            CardRegistActivity cardRegistActivity = (CardRegistActivity) getActivity();
            return 1;
        }
        CardRegistActivity cardRegistActivity2 = (CardRegistActivity) getActivity();
        return 2;
    }
}