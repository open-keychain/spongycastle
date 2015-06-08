package org.spongycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.math.ec.ECPoint;

/**
 * base class for an ECDSA Public Key.
 */
public class EdDSAPublicBCPGKey
    extends ECPublicBCPGKey
{
    /**
     * @param in the stream to read the packet from.
     */
    protected EdDSAPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        super(in);
    }

    public EdDSAPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        ECPoint point)
    {
        super(oid, point);
    }

    public EdDSAPublicBCPGKey(
           ASN1ObjectIdentifier oid,
           BigInteger encodedPoint)
        throws IOException
    {
           super(oid, encodedPoint);
    }
}
