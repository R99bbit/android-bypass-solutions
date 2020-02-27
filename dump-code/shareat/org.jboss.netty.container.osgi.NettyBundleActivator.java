package org.jboss.netty.container.osgi;

import org.jboss.netty.logging.InternalLoggerFactory;
import org.jboss.netty.logging.OsgiLoggerFactory;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;

public class NettyBundleActivator implements BundleActivator {
    private OsgiLoggerFactory loggerFactory;

    public void start(BundleContext ctx) throws Exception {
        this.loggerFactory = new OsgiLoggerFactory(ctx);
        InternalLoggerFactory.setDefaultFactory(this.loggerFactory);
    }

    public void stop(BundleContext ctx) throws Exception {
        if (this.loggerFactory != null) {
            InternalLoggerFactory.setDefaultFactory(this.loggerFactory.getFallback());
            this.loggerFactory.destroy();
            this.loggerFactory = null;
        }
    }
}