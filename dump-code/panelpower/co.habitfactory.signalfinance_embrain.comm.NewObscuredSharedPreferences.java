package co.habitfactory.signalfinance_embrain.comm;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.SharedPreferences.OnSharedPreferenceChangeListener;
import android.util.Base64;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class NewObscuredSharedPreferences implements SharedPreferences, SignalLibConsts {
    protected Context context;
    protected SharedPreferences delegate;
    protected byte[] iv;
    protected byte[] k;

    public class Editor implements android.content.SharedPreferences.Editor {
        protected android.content.SharedPreferences.Editor delegate;

        public android.content.SharedPreferences.Editor putStringSet(String str, Set<String> set) {
            return null;
        }

        public Editor() {
            this.delegate = NewObscuredSharedPreferences.this.delegate.edit();
        }

        public Editor putBoolean(String str, boolean z) {
            this.delegate.putString(str, NewObscuredSharedPreferences.this.encrypt(Boolean.toString(z), NewObscuredSharedPreferences.this.k, NewObscuredSharedPreferences.this.iv));
            return this;
        }

        public Editor putFloat(String str, float f) {
            this.delegate.putString(str, NewObscuredSharedPreferences.this.encrypt(Float.toString(f), NewObscuredSharedPreferences.this.k, NewObscuredSharedPreferences.this.iv));
            return this;
        }

        public Editor putInt(String str, int i) {
            this.delegate.putString(str, NewObscuredSharedPreferences.this.encrypt(Integer.toString(i), NewObscuredSharedPreferences.this.k, NewObscuredSharedPreferences.this.iv));
            return this;
        }

        public Editor putLong(String str, long j) {
            this.delegate.putString(str, NewObscuredSharedPreferences.this.encrypt(Long.toString(j), NewObscuredSharedPreferences.this.k, NewObscuredSharedPreferences.this.iv));
            return this;
        }

        public Editor putString(String str, String str2) {
            android.content.SharedPreferences.Editor editor = this.delegate;
            NewObscuredSharedPreferences newObscuredSharedPreferences = NewObscuredSharedPreferences.this;
            editor.putString(str, newObscuredSharedPreferences.encrypt(str2, newObscuredSharedPreferences.k, NewObscuredSharedPreferences.this.iv));
            return this;
        }

        public void apply() {
            this.delegate.apply();
        }

        public Editor clear() {
            this.delegate.clear();
            return this;
        }

        public boolean commit() {
            return this.delegate.commit();
        }

        public Editor remove(String str) {
            this.delegate.remove(str);
            return this;
        }
    }

    public Set<String> getStringSet(String str, Set<String> set) {
        return null;
    }

    public NewObscuredSharedPreferences(Context context2, SharedPreferences sharedPreferences) {
        this.delegate = sharedPreferences;
        this.context = context2;
        SharedPreferences sharedPreferences2 = context2.getSharedPreferences(SignalLibConsts.g_DataChannel, 0);
        String string = sharedPreferences2.getString(SignalLibConsts.PREF_API_USER_END_ACTION_K, null);
        String string2 = sharedPreferences2.getString(SignalLibConsts.PREF_API_USER_END_ACTION_IV, null);
        if (string == null || string2 == null) {
            android.content.SharedPreferences.Editor edit = sharedPreferences2.edit();
            this.k = randomByte(32);
            this.iv = randomByte(16);
            String encodeToString = Base64.encodeToString(this.k, 0);
            String encodeToString2 = Base64.encodeToString(this.iv, 0);
            edit.putString(SignalLibConsts.PREF_API_USER_END_ACTION_K, encodeToString);
            edit.putString(SignalLibConsts.PREF_API_USER_END_ACTION_IV, encodeToString2);
            edit.apply();
            return;
        }
        if (string != null) {
            this.k = Base64.decode(string, 0);
        }
        if (string2 != null) {
            this.iv = Base64.decode(string2, 0);
        }
    }

    public Editor edit() {
        return new Editor();
    }

    public Map<String, ?> getAll() {
        throw new UnsupportedOperationException();
    }

    public boolean getBoolean(String str, boolean z) {
        String string = this.delegate.getString(str, null);
        return string != null ? Boolean.parseBoolean(decrypt(string, this.k, this.iv)) : z;
    }

    public float getFloat(String str, float f) {
        String string = this.delegate.getString(str, null);
        return string != null ? Float.parseFloat(decrypt(string, this.k, this.iv)) : f;
    }

    public int getInt(String str, int i) {
        String string = this.delegate.getString(str, null);
        return string != null ? Integer.parseInt(decrypt(string, this.k, this.iv)) : i;
    }

    public long getLong(String str, long j) {
        String string = this.delegate.getString(str, null);
        return string != null ? Long.parseLong(decrypt(string, this.k, this.iv)) : j;
    }

    public String getString(String str, String str2) {
        String string = this.delegate.getString(str, null);
        return string != null ? decrypt(string, this.k, this.iv) : str2;
    }

    public boolean contains(String str) {
        return this.delegate.contains(str);
    }

    public void registerOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        this.delegate.registerOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
    }

    public void unregisterOnSharedPreferenceChangeListener(OnSharedPreferenceChangeListener onSharedPreferenceChangeListener) {
        this.delegate.unregisterOnSharedPreferenceChangeListener(onSharedPreferenceChangeListener);
    }

    /* access modifiers changed from: protected */
    public String encrypt(String str, byte[] bArr, byte[] bArr2) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
            Cipher instance = Cipher.getInstance("AES");
            instance.init(1, secretKeySpec, new IvParameterSpec(bArr2));
            return Base64.encodeToString(instance.doFinal(str.getBytes("UTF-8")), 0);
        } catch (Exception unused) {
            return null;
        }
    }

    /* access modifiers changed from: protected */
    public String decrypt(String str, byte[] bArr, byte[] bArr2) {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(bArr, "AES");
            Cipher instance = Cipher.getInstance("AES");
            instance.init(2, secretKeySpec, new IvParameterSpec(bArr2));
            return new String(instance.doFinal(Base64.decode(str, 0)), "UTF-8");
        } catch (Exception unused) {
            return null;
        }
    }

    public static byte[] randomByte(int i) {
        byte[] bArr = new byte[i];
        new SecureRandom().nextBytes(bArr);
        return bArr;
    }
}