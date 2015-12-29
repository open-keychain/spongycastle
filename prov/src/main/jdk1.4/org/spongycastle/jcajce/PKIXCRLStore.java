package org.spongycastle.jcajce;

import java.security.cert.CRL;
import java.util.Collection;

import org.spongycastle.util.Selector;
import org.spongycastle.util.Store;
import org.spongycastle.util.StoreException;

public interface PKIXCRLStore
    extends Store
{
    Collection getMatches(Selector selector)
        throws StoreException;
}
