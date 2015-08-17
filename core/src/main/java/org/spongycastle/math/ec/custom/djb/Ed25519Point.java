package org.spongycastle.math.ec.custom.djb;

import java.math.BigInteger;

import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.raw.Mod;
import org.spongycastle.math.raw.Nat256;

public class Ed25519Point extends ECPoint.AbstractFp
{
    /**
     * Create a point which encodes with point compression.
     *
     * @param curve the curve to use
     * @param x affine x co-ordinate
     * @param y affine y co-ordinate
     *
     * @deprecated Use ECCurve.createPoint to construct points
     */
    public Ed25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y)
    {
        this(curve, x, y, false);
    }

    Ed25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        super(curve, x, y, zs);

        this.withCompression = withCompression;
    }

    Ed25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        super(curve, x, y);

        this.withCompression = withCompression;
    }

    protected ECPoint detach()
    {
        return new Ed25519Point(null, getAffineXCoord(), getAffineYCoord());
    }

    public ECFieldElement getZCoord(int index)
    {
        if (index == 1)
        {
            return getJacobianModifiedW();
        }

        return super.getZCoord(index);
    }

    public ECPoint add(ECPoint b)
    {
        if (this.isInfinity())
        {
            return b;
        }
        if (b.isInfinity())
        {
            return this;
        }

        ECCurve curve = this.getCurve();

        Ed25519FieldElement X1 = (Ed25519FieldElement)this.x, Y1 = (Ed25519FieldElement)this.y;
        Ed25519FieldElement X2 = (Ed25519FieldElement)b.getXCoord(), Y2 = (Ed25519FieldElement)b.getYCoord();

        int[] t1 = Nat256.create();
        int[] t2 = Nat256.create();
        int[] t3 = Nat256.create();
        int[] one = Nat256.fromBigInteger(BigInteger.ONE);

        int[] dtemp = Ed25519Field.d;
        Ed25519Field.multiply(dtemp, X1.x, dtemp);
        Ed25519Field.multiply(dtemp, X2.x, dtemp);
        Ed25519Field.multiply(dtemp, Y1.x, dtemp);
        Ed25519Field.multiply(dtemp, Y2.x, dtemp);

        int[] x3 = Nat256.create();
        Ed25519Field.multiply(X1.x, Y2.x, t1);
        Ed25519Field.multiply(X2.x, Y1.x, t2);
        Ed25519Field.add(one, dtemp, t3);
        Mod.invert(Ed25519Field.P, t3, t3);
        Ed25519Field.add(t1, t2, x3);
        Ed25519Field.multiply(x3, t3, x3);

        int[] y3 = Nat256.create();
        Ed25519Field.multiply(Y1.x, Y2.x, t1);
        Ed25519Field.multiply(X1.x, X2.x, t2);
        Ed25519Field.subtract(one, dtemp, t3);
        Mod.invert(Ed25519Field.P, t3, t3);
        Ed25519Field.add(t1, t2, y3);
        Ed25519Field.multiply(y3, t3, y3);

        Ed25519FieldElement X3 = new Ed25519FieldElement(x3);
        Ed25519FieldElement Y3 = new Ed25519FieldElement(y3);

        return new Ed25519Point(curve, X3, Y3, this.withCompression);
    }

    public ECPoint twice()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECCurve curve = this.getCurve();

        ECFieldElement Y1 = this.y;
        if (Y1.isZero())
        {
            return curve.getInfinity();
        }

        return this.add(this);
    }

    public ECPoint twicePlus(ECPoint b)
    {
        if (this == b)
        {
            return threeTimes();
        }
        if (this.isInfinity())
        {
            return b;
        }
        if (b.isInfinity())
        {
            return twice();
        }

        ECFieldElement Y1 = this.y;
        if (Y1.isZero())
        {
            return b;
        }

        return this.add(this).add(b);
    }

    public ECPoint threeTimes()
    {
        if (this.isInfinity())
        {
            return this;
        }

        ECFieldElement Y1 = this.y;
        if (Y1.isZero())
        {
            return this;
        }

        return twiceJacobianModified(false).add(this);
    }

    public ECPoint negate()
    {
        if (this.isInfinity())
        {
            return this;
        }

        return new Ed25519Point(this.getCurve(), this.x, this.y.negate(), this.zs, this.withCompression);
    }

    protected Ed25519FieldElement calculateJacobianModifiedW(Ed25519FieldElement Z, int[] ZSquared)
    {
        Ed25519FieldElement a4 = (Ed25519FieldElement)this.getCurve().getA();
        if (Z.isOne())
        {
            return a4;
        }

        Ed25519FieldElement W = new Ed25519FieldElement();
        if (ZSquared == null)
        {
            ZSquared = W.x;
            Ed25519Field.square(Z.x, ZSquared);
        }
        Ed25519Field.square(ZSquared, W.x);
        Ed25519Field.multiply(W.x, a4.x, W.x);
        return W;
    }

    protected Ed25519FieldElement getJacobianModifiedW()
    {
        Ed25519FieldElement W = (Ed25519FieldElement)this.zs[1];
        if (W == null)
        {
            // NOTE: Rarely, twicePlus will result in the need for a lazy W1 calculation here
            this.zs[1] = W = calculateJacobianModifiedW((Ed25519FieldElement)this.zs[0], null);
        }
        return W;
    }

    protected Ed25519Point twiceJacobianModified(boolean calculateW)
    {
        Ed25519FieldElement X1 = (Ed25519FieldElement)this.x, Y1 = (Ed25519FieldElement)this.y,
            Z1 = (Ed25519FieldElement)this.zs[0], W1 = getJacobianModifiedW();

        int c;

        int[] M = Nat256.create();
        Ed25519Field.square(X1.x, M);
        c = Nat256.addBothTo(M, M, M);
        c += Nat256.addTo(W1.x, M);
        Ed25519Field.reduce27(c, M);

        int[] _2Y1 = Nat256.create();
        Ed25519Field.twice(Y1.x, _2Y1);

        int[] _2Y1Squared = Nat256.create();
        Ed25519Field.multiply(_2Y1, Y1.x, _2Y1Squared);

        int[] S = Nat256.create();
        Ed25519Field.multiply(_2Y1Squared, X1.x, S);
        Ed25519Field.twice(S, S);

        int[] _8T = Nat256.create();
        Ed25519Field.square(_2Y1Squared, _8T);
        Ed25519Field.twice(_8T, _8T);

        Ed25519FieldElement X3 = new Ed25519FieldElement(_2Y1Squared);
        Ed25519Field.square(M, X3.x);
        Ed25519Field.subtract(X3.x, S, X3.x);
        Ed25519Field.subtract(X3.x, S, X3.x);

        Ed25519FieldElement Y3 = new Ed25519FieldElement(S);
        Ed25519Field.subtract(S, X3.x, Y3.x);
        Ed25519Field.multiply(Y3.x, M, Y3.x);
        Ed25519Field.subtract(Y3.x, _8T, Y3.x);

        Ed25519FieldElement Z3 = new Ed25519FieldElement(_2Y1);
        if (!Nat256.isOne(Z1.x))
        {
            Ed25519Field.multiply(Z3.x, Z1.x, Z3.x);
        }

        Ed25519FieldElement W3 = null;
        if (calculateW)
        {
            W3 = new Ed25519FieldElement(_8T);
            Ed25519Field.multiply(W3.x, W1.x, W3.x);
            Ed25519Field.twice(W3.x, W3.x);
        }

        return new Ed25519Point(this.getCurve(), X3, Y3, new ECFieldElement[]{ Z3, W3 }, this.withCompression);
    }
}
