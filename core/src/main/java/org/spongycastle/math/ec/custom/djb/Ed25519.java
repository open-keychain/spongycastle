package org.spongycastle.math.ec.custom.djb;

import java.math.BigInteger;

import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.raw.Nat256;
import org.spongycastle.util.encoders.Hex;

public class Ed25519 extends ECCurve.AbstractFp
{
    public static final BigInteger q = Nat256.toBigInteger(Ed25519Field.P);

    private static final int Ed25519_DEFAULT_COORDS = COORD_JACOBIAN_MODIFIED;

    protected Ed25519Point infinity;

    public Ed25519()
    {
        super(q);

        this.infinity = new Ed25519Point(this, null, null);

        this.a = fromBigInteger(new BigInteger(1,
            Hex.decode("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144")));
        this.b = fromBigInteger(new BigInteger(1,
            Hex.decode("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864")));
        this.order = new BigInteger(1, Hex.decode("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"));
        this.cofactor = BigInteger.valueOf(8);

        this.coord = Ed25519_DEFAULT_COORDS;
    }

    protected ECCurve cloneCurve()
    {
        return new Ed25519();
    }

    public boolean supportsCoordinateSystem(int coord)
    {
        switch (coord)
        {
        case COORD_JACOBIAN_MODIFIED:
            return true;
        default:
            return false;
        }
    }

    public BigInteger getQ()
    {
        return q;
    }

    public int getFieldSize()
    {
        return q.bitLength();
    }

    public ECFieldElement fromBigInteger(BigInteger x)
    {
        return new Ed25519FieldElement(x);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        return new Ed25519Point(this, x, y, withCompression);
    }

    protected ECPoint createRawPoint(ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        return new Ed25519Point(this, x, y, zs, withCompression);
    }

    public ECPoint getInfinity()
    {
        return infinity;
    }
}
