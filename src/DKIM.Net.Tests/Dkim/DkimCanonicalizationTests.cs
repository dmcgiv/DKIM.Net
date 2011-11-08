/*
 * 
 * see http://www.dkim.org/specs/rfc4871-dkimbase.html#canonicalization
 * 
 * 3.4.6 Canonicalization Examples (INFORMATIVE)
 * 
 * */
using NUnit.Framework;

namespace DKIM.Tests
{

	[TestFixture]
	public class DkimCanonicalizationTests
	{
		[TestCase(@"A: X
B:Y	
	Z  

 C 
D 	 E


", @"a:X
b:Y Z
", @" C
D E
", DkimCanonicalizationAlgorithm.Relaxed)]
		[TestCase(@"A: X
B:Y	
	Z  

 C 
D 	 E


", @"A: X
B:Y	
	Z  
", @" C 
D 	 E
", DkimCanonicalizationAlgorithm.Simple)]
		public void Canonicalization2(string emailText, string canonicalizedHeaders, string canonicalizedBody, DkimCanonicalizationAlgorithm type)
		{
            
			var email = Email.Parse(emailText);

			Assert.AreEqual(canonicalizedBody, DkimCanonicalizer.CanonicalizeBody(email.Body, type), "body " + type);
			Assert.AreEqual(canonicalizedHeaders, DkimCanonicalizer.CanonicalizeHeaders(email.Headers, type, false, "A", "B"), "headers " + type);
            Assert.AreEqual(emailText, email.Raw);
		}
	}
}
