package org.spongycastle.jcajce;

import java.security.cert.Certificate;
import java.util.Collection;

import org.spongycastle.util.Selector;
import org.spongycastle.util.Store;
import org.spongycastle.util.StoreException;

public interface PKIXCertStore
    extends Store
{
    Collection getMatches(Selector selector)
        throws StoreException;
}
