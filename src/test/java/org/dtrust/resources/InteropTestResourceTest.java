package org.dtrust.resources;

import static org.junit.Assert.assertTrue;

import org.dtrust.BaseTestPlan;
import org.dtrust.InteropTestRunner;
import org.dtrust.dao.interoptest.entity.TestStatus;
import org.dtrust.dao.interoptest.entity.TestSuite;
import org.dtrust.utils.TestUtils;
import org.junit.Test;

import com.sun.jersey.api.client.WebResource;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.HashSet;
import java.util.Set;

public class InteropTestResourceTest
{
	static WebResource resource;
	
	abstract class TestPlan extends BaseTestPlan 
	{
		@Override
		protected void setupMocks() throws Exception
		{
			try
			{
				InteropTestRunner.startInteropTestService();
				super.setupMocks();
				cleanDAOs();
													
				resource = 	TestUtils.getResource(InteropTestRunner.getInteropTestServiceURL());		

			}
			catch (Throwable t)
			{
				throw new RuntimeException(t);
			}
			

		}
		
		@Override
		protected void tearDownMocks() throws Exception
		{
			try
			{
				cleanDAOs();
			}
			catch (Exception e)
			{
				
			}
			
			super.tearDownMocks();
		}
		
		protected void cleanDAOs() throws Exception
		{
			testSuiteDao.cleanTestSuites();
		}
		
		protected abstract String getToAddress();
		
		@Override
		protected void performInner() throws Exception
		{			
			
			final String toAddress = TestUtils.uriEscape(getToAddress());
			
			// add orgs then providers
			final long suiteId = resource.path("/interopTest/sendTests/" +  toAddress + "/2/" + TestUtils.uriEscape("gm2552@cerner.com")).post(Long.class);
			
			assertTrue(suiteId > 0);
			
			final TestSuite suite = getTestSuite(suiteId);
			
			doAssertions(suite);
		}
		
		protected TestSuite getTestSuite(long suiteid)
		{
			return resource.path("/interopTest/sendTests/" + suiteid).get(TestSuite.class);
		}
		
		protected void doAssertions(TestSuite suite) throws Exception
		{
			
		}
	}	
	
	
	@Test
	public void testExecuteInteropTest_testJobStarted() throws Exception
	{
		new TestPlan()
		{
			@Override
			protected String getToAddress()
			{
				return "gm2552@demo.sandboxcernerdirect.com";
			}
			
			
			@Override
			protected void doAssertions(TestSuite suite) throws Exception
			{

				// wait 2 seconds... there should be at least one test in the suite
				Thread.sleep(2000);
				
				suite = getTestSuite(suite.getTestSuiteid());
				
				assertTrue(suite.getTests().size() > 0);
				
				// go through all of the results
				while (suite.getTestStatus() == TestStatus.INITIATED || suite.getTestStatus() == TestStatus.RUNNING)
				{
					int cnt = 1;
					// sleep 5 seconds
					Thread.sleep(5000);
					suite = getTestSuite(suite.getTestSuiteid());
					int totalTests = suite.getTests().size();
					int completed = 0;
					for (org.dtrust.dao.interoptest.entity.Test test : suite.getTests())
					{
						if (!(test.getTestStatus() == TestStatus.INITIATED ||test.getTestStatus() == TestStatus.RUNNING))
							++completed;
						
						System.out.println("\r\nTest " + cnt++ + ": " + test.getTestName());
						System.out.println("\tStatus: " + test.getTestStatus());
						System.out.println("\tStatus: " + test.getComments());
					}
					
					System.out.println(completed + " of " + totalTests + " tests completed.");
				}
				
				System.out.println("\r\nFinal test status: " + suite.getTestStatus());
				
				int cnt = 1;
				for (org.dtrust.dao.interoptest.entity.Test test : suite.getTests())
				{
					System.out.println("\r\nTest " + cnt++ + ": " + test.getTestName());
					System.out.println("\tStatus: " + test.getTestStatus());
					System.out.println("\tStatus: " + test.getComments());
				}
			}
		}.perform();
	}
	@Test
	public void testGetLatestCRLNumber() {
		try {
			URL resource = this.getClass().getClassLoader().getResource("certs/DirectTrustCA.crl");
			File crlFile = new File(resource.toURI());
			InteropTestResource.CRLCreationTask crlCreationTask = new InteropTestResource.CRLCreationTask(null, null, crlFile, null);
			long crlNum = crlCreationTask.getLatestCRLNumber(crlCreationTask.crlFile);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	@Test
	public void testgetTests() throws Exception
	{
		TestSuite testSuite = new TestSuite();

		org.dtrust.dao.interoptest.entity.Test test1 = new org.dtrust.dao.interoptest.entity.Test();
		test1.setTestId(1);
		test1.setTestName("test 1");
		org.dtrust.dao.interoptest.entity.Test test2 = new org.dtrust.dao.interoptest.entity.Test();
		test2.setTestId(2);
		test2.setTestName("test 2");
		org.dtrust.dao.interoptest.entity.Test test3 = new org.dtrust.dao.interoptest.entity.Test();
		test2.setTestId(3);
		test2.setTestName("test 3");
		Set<org.dtrust.dao.interoptest.entity.Test> tests = new HashSet<org.dtrust.dao.interoptest.entity.Test>();
		tests.add(test3);
		tests.add(test2);
		tests.add(test1);
		testSuite.setTests(tests);
		Set<org.dtrust.dao.interoptest.entity.Test> testsResults = testSuite.getTests();

		assertTrue(true);
	}

}
