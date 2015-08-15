package org.spongycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.math.ec.ECPoint;

/**
 * base class for an EDDSA Public Key.
 */
public class EDDSAPublicBCPGKey
    extends ECPublicBCPGKey
{
    /**
     * @param in the stream to read the packet from.
     */
    protected EDDSAPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        super(in);
            StackTraceElement ste = Thread.currentThread().getStackTrace()[2];
            StringBuilder sb = new StringBuilder();
            sb.append(ste.getMethodName())        // メソッド名取得
                .append("(")
                .append(ste.getFileName())        // ファイル名取得
                .append(":")
                .append(ste.getLineNumber())    // 行番号取得
                .append(")");
            System.out.println(sb.toString());
    }

    public EDDSAPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        ECPoint point)
    {
        super(oid, point);
    }

    public EDDSAPublicBCPGKey(
           ASN1ObjectIdentifier oid,
           BigInteger encodedPoint)
        throws IOException
    {
           super(oid, encodedPoint);
    }
}
