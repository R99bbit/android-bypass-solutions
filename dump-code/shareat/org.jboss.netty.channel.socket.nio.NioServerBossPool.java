package org.jboss.netty.channel.socket.nio;

import java.util.concurrent.Executor;
import org.jboss.netty.util.ThreadNameDeterminer;

public class NioServerBossPool extends AbstractNioBossPool<NioServerBoss> {
    private final ThreadNameDeterminer determiner;

    public NioServerBossPool(Executor bossExecutor, int bossCount, ThreadNameDeterminer determiner2) {
        super(bossExecutor, bossCount, false);
        this.determiner = determiner2;
        init();
    }

    public NioServerBossPool(Executor bossExecutor, int bossCount) {
        this(bossExecutor, bossCount, null);
    }

    /* access modifiers changed from: protected */
    public NioServerBoss newBoss(Executor executor) {
        return new NioServerBoss(executor, this.determiner);
    }
}