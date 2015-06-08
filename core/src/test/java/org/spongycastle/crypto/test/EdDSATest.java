package org.spongycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import java.math.BigInteger;
import java.nio.charset.Charset;

import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.digests.SHA224Digest;
import org.spongycastle.crypto.digests.SHA256Digest;
import org.spongycastle.crypto.generators.DSAKeyPairGenerator;
import org.spongycastle.crypto.generators.DSAParametersGenerator;
import org.spongycastle.crypto.params.DSAKeyGenerationParameters;
import org.spongycastle.crypto.params.DSAParameterGenerationParameters;
import org.spongycastle.crypto.params.DSAParameters;
import org.spongycastle.crypto.params.DSAPrivateKeyParameters;
import org.spongycastle.crypto.params.DSAPublicKeyParameters;
import org.spongycastle.crypto.params.DSAValidationParameters;
import org.spongycastle.crypto.params.ParametersWithRandom;
import org.spongycastle.crypto.signers.EdDSASigner;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.BigIntegers;
import org.spongycastle.util.encoders.Hex;
import org.spongycastle.util.test.FixedSecureRandom;
import org.spongycastle.util.test.SimpleTest;

public class EdDSATest
    extends SimpleTest
{
    static final String HEXES = "0123456789abcdef";

    public static String getHex( byte [] raw ) {
        if ( raw == null ) {
            return null;
        }
        final StringBuilder hex = new StringBuilder( 2 * raw.length );
        for ( final byte b : raw ) {
            hex.append(HEXES.charAt((b & 0xF0) >> 4))
            .append(HEXES.charAt((b & 0x0F)));
        }
        return hex.toString();
    }

    public String getName()
    {
        return "EdDSA";
    }

    public void performTest()
    {
        byte[] sk = new byte[32];
        Arrays.fill(sk, (byte)0);
        byte[] pk = EdDSASigner.publickey(sk);
        System.out.println("publickey for 0 is \"" + getHex(pk) + "\"");
        System.out.println("encodeint 0 = " + getHex(EdDSASigner.encodeint(BigInteger.ZERO)));
        System.out.println("encodeint 1 = " + getHex(EdDSASigner.encodeint(BigInteger.ONE)));
        System.out.println("encodeint 10 = " + getHex(EdDSASigner.encodeint(BigInteger.TEN)));
        BigInteger[] zerozero = new BigInteger[]{BigInteger.ZERO,BigInteger.ZERO};
        BigInteger[] oneone = new BigInteger[]{BigInteger.ONE,BigInteger.ONE};
        BigInteger[] tenzero = new BigInteger[]{BigInteger.TEN,BigInteger.ZERO};
        BigInteger[] oneten = new BigInteger[]{BigInteger.ONE,BigInteger.TEN};
        BigInteger[] pkr = new BigInteger[]{new BigInteger("9639205628789703341510410801487549615560488670885798085067615194958049462616"), new BigInteger("18930617471878267742194159801949745215346600387277955685031939302387136031291")};
        byte[] message = "This is a secret message".getBytes(Charset.forName("UTF-8"));
        byte[] signature = EdDSASigner.generateSignature(message, sk, pk);
        System.out.println("signature(\"This is a secret message\") = "+getHex(signature));
        try
        {
            if (!EdDSASigner.verifySignature(signature,message,pk))
            {
                fail("Fail verification.");
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            fail("Fail verification.");
        }
        fail("succeed.");
    }

    public static void main(
        String[]    args)
    {
        runTest(new EdDSATest());
    }
}
