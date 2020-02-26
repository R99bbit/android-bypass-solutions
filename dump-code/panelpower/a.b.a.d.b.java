package a.b.a.d;

import a.a.a.a.a;
import com.kakao.network.ServerProtocol;
import com.loplat.placeengine.OnPlengiListener;
import com.loplat.placeengine.PlaceEngineBase;
import com.loplat.placeengine.PlengiResponse;
import com.loplat.placeengine.PlengiResponse.Location;
import com.loplat.placeengine.cloud.RequestMessage.CellEntity;

/* compiled from: CellLocationUpdater */
class b implements OnPlengiListener {

    /* renamed from: a reason: collision with root package name */
    public final /* synthetic */ OnPlengiListener f20a;
    public final /* synthetic */ int b;
    public final /* synthetic */ int c;
    public final /* synthetic */ c d;

    public b(c cVar, OnPlengiListener onPlengiListener, int i, int i2) {
        this.d = cVar;
        this.f20a = onPlengiListener;
        this.b = i;
        this.c = i2;
    }

    public void onFail(PlengiResponse plengiResponse) {
        if (plengiResponse != null) {
            CellEntity cellEntity = (CellEntity) this.d.n.get(Integer.valueOf(this.c));
            StringBuilder a2 = a.a(" @");
            a2.append(this.c);
            a2.append(":Cell ");
            a2.append(PlengiResponse.LOCATION_ACQUISITION_FAIL);
            String sb = a2.toString();
            OnPlengiListener onPlengiListener = this.f20a;
            if (onPlengiListener != null) {
                plengiResponse.result = -1;
                plengiResponse.errorReason = sb;
                onPlengiListener.onFail(plengiResponse);
            } else if (cellEntity != null) {
                this.d.k;
                this.d.a();
            }
        }
    }

    public void onSuccess(PlengiResponse plengiResponse) {
        if (plengiResponse != null) {
            Location location = plengiResponse.location;
            if (location != null) {
                plengiResponse.type = 5;
                OnPlengiListener onPlengiListener = this.f20a;
                if (onPlengiListener != null) {
                    onPlengiListener.onSuccess(plengiResponse);
                } else {
                    int cellId = location.getCellId();
                    if (cellId > 0) {
                        CellEntity cellEntity = (CellEntity) this.d.n.get(Integer.valueOf(cellId));
                        if (cellEntity != null) {
                            String str = this.b == 1 ? "STAY" : "MOVE";
                            this.d.k;
                            StringBuilder sb = new StringBuilder();
                            sb.append(ServerProtocol.AUTHORIZATION_HEADER_DELIMITER);
                            sb.append(str);
                            sb.append(":");
                            sb.append(cellEntity);
                            sb.toString();
                            PlaceEngineBase.forwardMessageToClient(plengiResponse);
                        }
                    }
                }
                this.d.a();
            }
        }
    }
}