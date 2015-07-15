package org.spongycastle.math.ec.custom.djb;

import org.spongycastle.math.ec.ECCurve;
import org.spongycastle.math.ec.ECFieldElement;
import org.spongycastle.math.ec.ECPoint;
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

    /**
     * Create a point that encodes with or without point compresion.
     *
     * @param curve the curve to use
     * @param x affine x co-ordinate
     * @param y affine y co-ordinate
     * @param withCompression if true encode with point compression
     *
     * @deprecated per-point compression property will be removed, refer {@link #getEncoded(boolean)}
     */
    public Ed25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y, boolean withCompression)
    {
        super(curve, x, y);

        if ((x == null) != (y == null))
        {
            throw new IllegalArgumentException("Exactly one of the field elements is null");
        }

        this.withCompression = withCompression;
    }

    Ed25519Point(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs, boolean withCompression)
    {
        super(curve, x, y, zs);

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
        if (this == b)
        {
            return twice();
        }

        ECCurve curve = this.getCurve();

        Ed25519FieldElement X1 = (Ed25519FieldElement)this.x, Y1 = (Ed25519FieldElement)this.y,
            Z1 = (Ed25519FieldElement)this.zs[0];
        Ed25519FieldElement X2 = (Ed25519FieldElement)b.getXCoord(), Y2 = (Ed25519FieldElement)b.getYCoord(),
            Z2 = (Ed25519FieldElement)b.getZCoord(0);

        int c;
        int[] tt1 = Nat256.createExt();
        int[] t2 = Nat256.create();
        int[] t3 = Nat256.create();
        int[] t4 = Nat256.create();

        boolean Z1IsOne = Z1.isOne();
        int[] U2, S2;
        if (Z1IsOne)
        {
            U2 = X2.x;
            S2 = Y2.x;
        }
        else
        {
            S2 = t3;
            Ed25519Field.square(Z1.x, S2);

            U2 = t2;
            Ed25519Field.multiply(S2, X2.x, U2);

            Ed25519Field.multiply(S2, Z1.x, S2);
            Ed25519Field.multiply(S2, Y2.x, S2);
        }

        boolean Z2IsOne = Z2.isOne();
        int[] U1, S1;
        if (Z2IsOne)
        {
            U1 = X1.x;
            S1 = Y1.x;
        }
        else
        {
            S1 = t4;
            Ed25519Field.square(Z2.x, S1);

            U1 = tt1;
            Ed25519Field.multiply(S1, X1.x, U1);

            Ed25519Field.multiply(S1, Z2.x, S1);
            Ed25519Field.multiply(S1, Y1.x, S1);
        }

        int[] H = Nat256.create();
        Ed25519Field.subtract(U1, U2, H);

        int[] R = t2;
        Ed25519Field.subtract(S1, S2, R);

        // Check if b == this or b == -this
        if (Nat256.isZero(H))
        {
            if (Nat256.isZero(R))
            {
                // this == b, i.e. this must be doubled
                return this.twice();
            }

            // this == -b, i.e. the result is the point at infinity
            return curve.getInfinity();
        }

        int[] HSquared = Nat256.create();
        Ed25519Field.square(H, HSquared);

        int[] G = Nat256.create();
        Ed25519Field.multiply(HSquared, H, G);

        int[] V = t3;
        Ed25519Field.multiply(HSquared, U1, V);

        Ed25519Field.negate(G, G);
        Nat256.mul(S1, G, tt1);

        c = Nat256.addBothTo(V, V, G);
        Ed25519Field.reduce27(c, G);

        Ed25519FieldElement X3 = new Ed25519FieldElement(t4);
        Ed25519Field.square(R, X3.x);
        Ed25519Field.subtract(X3.x, G, X3.x);

        Ed25519FieldElement Y3 = new Ed25519FieldElement(G);
        Ed25519Field.subtract(V, X3.x, Y3.x);
        Ed25519Field.multiplyAddToExt(Y3.x, R, tt1);
        Ed25519Field.reduce(tt1, Y3.x);

        Ed25519FieldElement Z3 = new Ed25519FieldElement(H);
        if (!Z1IsOne)
        {
            Ed25519Field.multiply(Z3.x, Z1.x, Z3.x);
        }
        if (!Z2IsOne)
        {
            Ed25519Field.multiply(Z3.x, Z2.x, Z3.x);
        }

        int[] Z3Squared = (Z1IsOne && Z2IsOne) ? HSquared : null;

        // TODO If the result will only be used in a subsequent addition, we don't need W3
        Ed25519FieldElement W3 = calculateJacobianModifiedW((Ed25519FieldElement)Z3, Z3Squared);

        ECFieldElement[] zs = new ECFieldElement[]{ Z3, W3 };

        return new Ed25519Point(curve, X3, Y3, zs, this.withCompression);
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

        return twiceJacobianModified(true);
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

        return twiceJacobianModified(false).add(b);
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
