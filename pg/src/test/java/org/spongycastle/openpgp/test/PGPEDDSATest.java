package org.spongycastle.openpgp.test;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Iterator;
import org.spongycastle.asn1.nist.NISTNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.bcpg.HashAlgorithmTags;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.ECKeyPairGenerator;
import org.spongycastle.crypto.params.ECKeyGenerationParameters;
import org.spongycastle.crypto.params.ECNamedDomainParameters;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPEncryptedData;
import org.spongycastle.openpgp.PGPKeyPair;
import org.spongycastle.openpgp.PGPKeyRingGenerator;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPPublicKeyRingCollection;
import org.spongycastle.openpgp.PGPPrivateKey;
import org.spongycastle.openpgp.PGPSecretKey;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.spongycastle.openpgp.PGPSignature;
import org.spongycastle.openpgp.PGPSignatureGenerator;
import org.spongycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.spongycastle.openpgp.PGPUtil;
import org.spongycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.spongycastle.openpgp.operator.PGPDigestCalculator;
import org.spongycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.spongycastle.openpgp.operator.bc.BcPGPKeyPair;
import org.spongycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.spongycastle.openpgp.operator.jcajce.JcePBEProtectionRemoverFactory;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.spongycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.spongycastle.util.Arrays;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.test.SimpleTest;

public class PGPEDDSATest
    extends SimpleTest
{
    public void performTest()
        throws Exception
    {
        importKeyTest2();
        return;
    //     signKey();

    //     KeyPairGenerator        keyGen = KeyPairGenerator.getInstance("EDDSA", "SC");

    //     keyGen.initialize(new ECGenParameterSpec("ed25519"));

    //     KeyPair kpSign = keyGen.generateKeyPair();

    //     PGPKeyPair ecdsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.EDDSA, kpSign, new Date());

    //     //
    //     // try a signature
    //     //
    //     PGPSignatureGenerator signGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PGPPublicKey.EDDSA, HashAlgorithmTags.SHA512).setProvider("SC"));

    //     signGen.init(PGPSignature.BINARY_DOCUMENT, ecdsaKeyPair.getPrivateKey());

    //     signGen.update("hello world!".getBytes());

    //     PGPSignature sig = signGen.generate();

    //     sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("SC"), ecdsaKeyPair.getPublicKey());

    //     sig.update("hello world!".getBytes());

    //     if (!sig.verify())
    //     {
    //         fail("signature failed to verify!");
    //     }

    //     //
    //     // generate a key ring
    //     //
    //     char[] passPhrase = "test".toCharArray();
    //     PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
    //     PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, ecdsaKeyPair,
    //              "test@bouncycastle.org", sha1Calc, null, null, new JcaPGPContentSignerBuilder(ecdsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("SC").build(passPhrase));

    //     PGPPublicKeyRing pubRing = keyRingGen.generatePublicKeyRing();

    //     PGPSecretKeyRing secRing = keyRingGen.generateSecretKeyRing();

    //     KeyFingerPrintCalculator fingerCalc = new JcaKeyFingerprintCalculator();

    //     PGPPublicKeyRing pubRingEnc = new PGPPublicKeyRing(pubRing.getEncoded(), fingerCalc);

    //     if (!Arrays.areEqual(pubRing.getEncoded(), pubRingEnc.getEncoded()))
    //     {
    //         fail("public key ring encoding failed");
    //     }

    //     for (Iterator it = pubRingEnc.getPublicKey().getSignatures(); it.hasNext();)
    //     {
    //         PGPSignature certification = (PGPSignature)it.next();

    //         certification.init(new JcaPGPContentVerifierBuilderProvider().setProvider("SC"), pubRingEnc.getPublicKey());

    //         if (!certification.verifyCertification((String)pubRingEnc.getPublicKey().getUserIDs().next(), pubRingEnc.getPublicKey()))
    //         {
    //             fail("self certification does not verify");
    //         }
    //     }

    //     PGPSecretKeyRing secRingEnc = new PGPSecretKeyRing(secRing.getEncoded(), fingerCalc);

    //     if (!Arrays.areEqual(secRing.getEncoded(), secRingEnc.getEncoded()))
    //     {
    //         fail("secret key ring encoding failed");
    //     }


    //     //
    //     // try a signature using encoded key
    //     //
    //     signGen = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PGPPublicKey.EDDSA, HashAlgorithmTags.SHA256).setProvider("SC"));

    //     signGen.init(PGPSignature.BINARY_DOCUMENT, secRing.getSecretKey().extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("SC").build(passPhrase)));

    //     signGen.update("hello world!".getBytes());

    //     sig = signGen.generate();

    //     sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider("SC"), secRing.getSecretKey().getPublicKey());

    //     sig.update("hello world!".getBytes());

    //     if (!sig.verify())
    //     {
    //         fail("re-encoded signature failed to verify!");
    //     }
    }

    private void importKeyTest()
        throws Exception
    {
        byte[] testPubKey =
            Base64.decode(
                "mDMEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku" +
                "Q+47JAa0NEVkRFNBIHNhbXBsZSBrZXkgMSAoZHJhZnQta29jaC1lZGRzYS1mb3It" +
                "b3BlbnBncC0wMCmIeQQTFggAIQUCU/NfCwIbAwULCQgHAgYVCAkKCwIEFgIDAQIe" +
                "AQIXgAAKCRCM/eEhl5ZamnNOAP9pKn5wz3jPsgy9p65zxz1+xJEr/cczFQx/tYkk" +
                "49tkeAD+P9jJE4SFD2lVofxn1e22H7YLvcVyHDOA9gpYWTNXiAU=");

        byte[] testPrivKey =
            Base64.decode(
                "lIYEU/NfCxYJKwYBBAHaRw8BAQdAPwmJlL3ZFu1AUxl5NOSofIBzOhKA1i+AEJku" +
                "Q+47JAb+BwMCeZTNZ5R2udDknlhWE5VnJaHe+HFieLlfQA+nibymcJS5lTYL7NP+" +
                "3CY63ylHwHoS7PuPLpdbEvROJ60u6+a/bSe86jRcJODR6rN2iG9v5LQ0RWREU0Eg" +
                "c2FtcGxlIGtleSAxIChkcmFmdC1rb2NoLWVkZHNhLWZvci1vcGVucGdwLTAwKYh5" +
                "BBMWCAAhBQJT818LAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEIz94SGX" +
                "llqac04A/2kqfnDPeM+yDL2nrnPHPX7EkSv9xzMVDH+1iSTj22R4AP4/2MkThIUP" +
                "aVWh/GfV7bYftgu9xXIcM4D2ClhZM1eIBQ==");

        PGPUtil.setDefaultProvider("SC");

        //
        // Read the public key
        //
        System.out.println("START EDDSA");
        PGPPublicKeyRing        pubKeyRing = new PGPPublicKeyRing(testPubKey, new JcaKeyFingerprintCalculator());

        for (Iterator it = pubKeyRing.getPublicKey().getSignatures(); it.hasNext();)
        {
            PGPSignature certification = (PGPSignature)it.next();

            certification.init(new JcaPGPContentVerifierBuilderProvider().setProvider("SC"), pubKeyRing.getPublicKey());

            if (!certification.verifyCertification((String)pubKeyRing.getPublicKey().getUserIDs().next(), pubKeyRing.getPublicKey()))
            {
                fail("self certification does not verify");
            }
        }
        System.out.println("FINISH EDDSA");

        //
        // Read the private key
        //
        PGPSecretKeyRing        secretKeyRing = new PGPSecretKeyRing(testPrivKey, new JcaKeyFingerprintCalculator());
    }

    private void importKeyTest2()
        throws Exception
    {
        PGPPublicKeyRingCollection pubRingCollection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(this.getClass().getResourceAsStream("eddsa-sample-1-pub.asc")), new JcaKeyFingerprintCalculator());
        Iterator uit = pubRingCollection.getKeyRings();
        System.out.println("START EDDSA");
        while (uit.hasNext())
        {
            PGPPublicKeyRing pubKeyRing = (PGPPublicKeyRing)uit.next();
            for (Iterator it = pubKeyRing.getPublicKey().getSignatures(); it.hasNext();)
            {
                PGPSignature certification = (PGPSignature)it.next();

                certification.init(new JcaPGPContentVerifierBuilderProvider().setProvider("SC"), pubKeyRing.getPublicKey());

                if (!certification.verifyCertification((String)pubKeyRing.getPublicKey().getUserIDs().next(), pubKeyRing.getPublicKey()))
                {
                    fail("self certification does not verify");
                }
            }
        }
        System.out.println("FINISH EDDSA");
    }

    // private void signKey()
    //     throws Exception
    // {
    //     char[]              passPhrase = "hello".toCharArray();
    //     KeyPairGenerator    rsaKpg = KeyPairGenerator.getInstance("RSA", "SC");

    //     rsaKpg.initialize(512);

    //     KeyPair           rsaKp = rsaKpg.generateKeyPair();
    //     PGPKeyPair        rsaKeyPair1 = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, rsaKp, new Date());
    //     PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
    //     PGPKeyRingGenerator    keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, rsaKeyPair1,
    //                         "test", sha1Calc, null, null, new JcaPGPContentSignerBuilder(PGPPublicKey.RSA_SIGN, HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256).setProvider("SC").build(passPhrase));

    //     KeyPairGenerator        eddsaKpg = KeyPairGenerator.getInstance("EDDSA", "SC");
    //     eddsaKpg.initialize(new ECGenParameterSpec("ed25519"));
    //     KeyPair eddsaKp = eddsaKpg.generateKeyPair();
    //     PGPKeyPair eddsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.EDDSA, eddsaKp, new Date());

    //     keyRingGen.addSubKey(eddsaKeyPair);

    //     PGPSecretKeyRing       keyRing = keyRingGen.generateSecretKeyRing();

    //     keyRing.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(passPhrase));

    //     PGPPublicKeyRing        pubRing = keyRingGen.generatePublicKeyRing();

    //     PGPPublicKey             masterPublicKey  = rsaKeyPair1.getPublicKey();
    //     PGPPrivateKey            masterPrivateKey = rsaKeyPair1.getPrivateKey();
    //     PGPPublicKey             subPublicKey     = eddsaKeyPair.getPublicKey();
    //     PGPPrivateKey            subPrivateKey    = eddsaKeyPair.getPrivateKey();

    //     PGPSignatureSubpacketGenerator subHashedPacketsGen = new PGPSignatureSubpacketGenerator();
    //     subHashedPacketsGen.setSignatureCreationTime(false, new Date());
    //     PGPSignatureGenerator subSigGen =
    //         new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(PGPPublicKey.EDDSA, HashAlgorithmTags.SHA512).setProvider("SC"));
    //     subSigGen.init(PGPSignature.PRIMARYKEY_BINDING, subPrivateKey);
    //     subSigGen.setHashedSubpackets(subHashedPacketsGen.generate());
    //     PGPSignature sig = subSigGen.generateCertification(masterPublicKey, subPublicKey);

    //     if (sig.getSignatureType() == PGPSignature.PRIMARYKEY_BINDING)
    //     {
    //         sig.init(new BcPGPContentVerifierBuilderProvider(), subPublicKey);
    //         if (!sig.verifyCertification(masterPublicKey, subPublicKey))
    //         {
    //             fail("failed to verify sub-key signature.");
    //         }
    //     }
    // }

    public String getName()
    {
        return "PGPEDDSATest";
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new PGPECDSATest());
    }
}
