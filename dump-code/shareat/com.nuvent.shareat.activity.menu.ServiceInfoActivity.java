package com.nuvent.shareat.activity.menu;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;
import com.nuvent.shareat.R;
import com.nuvent.shareat.ShareatApp;
import com.nuvent.shareat.activity.MainActionBarActivity;
import com.nuvent.shareat.api.ApiUrl;
import com.nuvent.shareat.api.Request.RequestHandler;
import com.nuvent.shareat.api.common.CompanyAddressApi;
import com.nuvent.shareat.dialog.TermsDialog;
import com.nuvent.shareat.model.PaydisModel;
import com.nuvent.shareat.model.PaydisResultModel;
import com.nuvent.shareat.util.GAEvent;
import java.util.Iterator;

public class ServiceInfoActivity extends MainActionBarActivity {
    public void onClickVersion(View view) {
        pushActivity(new Intent(this, VersionInfoActivity.class));
    }

    public void onClickMenu(View view) {
        String url = ApiUrl.TERMS_CUSTOMER_TERMS;
        switch (view.getId()) {
            case R.id.openSourceLayout /*2131296959*/:
                url = ApiUrl.TERMS_OPEN_LICENSE;
                break;
            case R.id.paymentLayout /*2131297047*/:
                url = ApiUrl.TERMS_PAY_TERMS;
                break;
            case R.id.policyLayour /*2131297119*/:
                url = ApiUrl.TERMS_USER_INFO_TERMS;
                break;
            case R.id.termsGpsLayout /*2131297401*/:
                url = ApiUrl.TERMS_LOCATION_SERVICE;
                break;
            case R.id.termsLayout /*2131297402*/:
                url = ApiUrl.TERMS_CUSTOMER_TERMS;
                break;
        }
        new TermsDialog(this, url).show();
    }

    /* access modifiers changed from: protected */
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_service_info, 2);
        GAEvent.onGAScreenView(this, R.string.ga_service_info);
        showSubActionbar();
        showFavoriteButton(false);
        setTitle("\uc11c\ube44\uc2a4\uc815\ubcf4");
        ((TextView) findViewById(R.id.versionLabel)).setText(ShareatApp.getInstance().getAppVersionName());
        requestCompanyAddressApi();
    }

    private void requestCompanyAddressApi() {
        new CompanyAddressApi(this).request(new RequestHandler() {
            public void onResult(Object result) {
                PaydisResultModel model = (PaydisResultModel) result;
                if (model.getResult_list() != null && model.getResult_list().size() > 0) {
                    Iterator<PaydisModel> it = model.getResult_list().iterator();
                    while (it.hasNext()) {
                        PaydisModel pmodel = it.next();
                        if (true == "ADDRESS".equals(pmodel.getCode_id())) {
                            ((TextView) ServiceInfoActivity.this.findViewById(R.id.company_address)).setText(pmodel.getCode_value());
                            return;
                        }
                    }
                }
            }

            public void onFailure(Exception exception) {
            }
        });
    }
}