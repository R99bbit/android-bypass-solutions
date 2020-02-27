package bolts;

import android.net.Uri;
import java.util.Collections;
import java.util.List;

public class AppLink {
    private Uri sourceUrl;
    private List<Target> targets;
    private Uri webUrl;

    public static class Target {
        private final String appName;
        private final String className;
        private final String packageName;
        private final Uri url;

        public Target(String packageName2, String className2, Uri url2, String appName2) {
            this.packageName = packageName2;
            this.className = className2;
            this.url = url2;
            this.appName = appName2;
        }

        public Uri getUrl() {
            return this.url;
        }

        public String getAppName() {
            return this.appName;
        }

        public String getClassName() {
            return this.className;
        }

        public String getPackageName() {
            return this.packageName;
        }
    }

    public AppLink(Uri sourceUrl2, List<Target> targets2, Uri webUrl2) {
        this.sourceUrl = sourceUrl2;
        this.targets = targets2 == null ? Collections.emptyList() : targets2;
        this.webUrl = webUrl2;
    }

    public Uri getSourceUrl() {
        return this.sourceUrl;
    }

    public List<Target> getTargets() {
        return Collections.unmodifiableList(this.targets);
    }

    public Uri getWebUrl() {
        return this.webUrl;
    }
}