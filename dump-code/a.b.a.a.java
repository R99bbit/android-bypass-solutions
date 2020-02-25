package a.b.a;

import android.os.Parcel;
import android.os.Parcelable.Creator;
import com.loplat.placeengine.ClientBaseInfo;

/* compiled from: ClientBaseInfo */
class a implements Creator<ClientBaseInfo> {
    public Object createFromParcel(Parcel parcel) {
        return new ClientBaseInfo(parcel);
    }

    public Object[] newArray(int i) {
        return new ClientBaseInfo[i];
    }
}