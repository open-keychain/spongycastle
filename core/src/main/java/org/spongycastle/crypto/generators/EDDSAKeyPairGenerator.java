package org.spongycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.spongycastle.crypto.KeyGenerationParameters;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECPrivateKeyParameters;
import org.spongycastle.crypto.params.ECPublicKeyParameters;
import org.spongycastle.crypto.signers.EDDSASigner;
import org.spongycastle.math.ec.custom.djb.*;
import org.spongycastle.math.ec.ECConstants;
import org.spongycastle.math.ec.ECMultiplier;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointCombMultiplier;
import org.spongycastle.math.ec.ReferenceMultiplier;
import org.spongycastle.math.ec.WNafUtil;
import org.spongycastle.math.raw.Nat256;

public class EDDSAKeyPairGenerator
    implements AsymmetricCipherKeyPairGenerator, ECConstants
{
    ECDomainParameters  params;
    SecureRandom        random;

    static final int b = 256;
    static final BigInteger q = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949");
    static final BigInteger qm2 = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819947");
    static final BigInteger qp3 = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819952");
    static final BigInteger l = new BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989");
    static final BigInteger d = new BigInteger("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740");
    static final BigInteger I = new BigInteger("19681161376707505956807079304988542015446066515923890162744021073123829784752");
    static final BigInteger By = new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960");
    static final BigInteger Bx = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
    static final BigInteger[] B = {Bx.mod(q),By.mod(q)};
    static final BigInteger un = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819967");

    public void init(
        KeyGenerationParameters param)
    {
        ECKeyGenerationParameters  ecP = (ECKeyGenerationParameters)param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();

        if (this.random == null)
        {
            this.random = new SecureRandom();
        }
    }

    public AsymmetricCipherKeyPair generateKeyPair()
    {
        BigInteger n = params.getN();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;

        BigInteger d;
        for (;;)
        {
            d = new BigInteger(nBitLength, random);

            if (d.compareTo(TWO) < 0  || (d.compareTo(n) >= 0))
            {
                continue;
            }

            /*
             * Require a minimum weight of the NAF representation, since low-weight primes may be
             * weak against a version of the number-field-sieve for the discrete-logarithm-problem.
             *
             * See "The number field sieve for integers of low weight", Oliver Schirokauer.
             */
            if (WNafUtil.getNafWeight(d) < minWeight)
            {
                continue;
            }

            break;
        }

        byte[] h = EDDSASigner.H(d.toByteArray());
        BigInteger a = BigInteger.valueOf(2).pow(b-2);
        for (int i=3;i<(b-2);i++) {
            BigInteger apart = BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(EDDSASigner.bit(h,i)));
            a = a.add(apart);
        }
        ECPoint pe = params.getCurve().createPoint(Bx, By, true);
        ECMultiplier basePointMultiplier = createBasePointMultiplier();
        ECPoint p = basePointMultiplier.multiply(pe, a);
        BigInteger[] A = new BigInteger[]{p.getXCoord().toBigInteger(), p.getYCoord().toBigInteger()};

        ECPoint Q = params.getCurve().createPoint(A[0], A[1]);

        return new AsymmetricCipherKeyPair(
            new ECPublicKeyParameters(Q, params),
            new ECPrivateKeyParameters(d, params));
    }

    protected ECMultiplier createBasePointMultiplier()
    {
        return new ReferenceMultiplier();
    }
}