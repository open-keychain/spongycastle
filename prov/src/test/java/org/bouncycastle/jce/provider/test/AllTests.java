package org.bouncycastle.jce.provider.test;

import java.security.Security;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.test.rsa3.RSA3CertTest;
import org.bouncycastle.util.test.SimpleTestResult;

public class AllTests
    extends TestCase
{
    public void testJCE()
    {   
        org.bouncycastle.util.test.Test[] tests = RegressionTest.tests;
        
        for (int i = 0; i != tests.length; i++)
        {
            org.bouncycastle.util.test.Test test = tests[i];
            System.err.println(test.getName());
            SimpleTestResult result = (SimpleTestResult) test.perform();
            System.err.println(test.getName()+" "+result);
            
            if (!result.isSuccessful())
            {
                if (result.getException() != null)
                {
                    result.getException().printStackTrace();
                }
                fail(result.toString());
            }
        }
    }
    
    public static void main (String[] args)
    {
        junit.textui.TestRunner.run(suite());
    }
    
    public static Test suite()
    {
        TestSuite suite = new TestSuite("JCE Tests");
        
        if (Security.getProvider("BC") == null)
        {
            Security.addProvider(new BouncyCastleProvider());  
        }
        
        suite.addTestSuite(RSA3CertTest.class);
        suite.addTestSuite(AllTests.class);
        
        return suite;
    }
}
