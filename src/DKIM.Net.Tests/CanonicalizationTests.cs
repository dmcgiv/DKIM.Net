/*
 * 
 * see http://www.dkim.org/specs/rfc4871-dkimbase.html#canonicalization
 * 
 * 3.4.6 Canonicalization Examples (INFORMATIVE)
 * 
 * */
using NUnit.Framework;

namespace McGiv.DKIM.Tests
{

	[TestFixture]
	public class CanonicalizationTests
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
", CanonicalizationAlgorithm.Relaxed)]
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
", CanonicalizationAlgorithm.Simple)]
		public void Canonicalization2(string emailText, string canonicalizedHeaders, string canonicalizedBody, CanonicalizationAlgorithm type)
		{

			var email = Email.Parse(emailText);

			Assert.AreEqual(canonicalizedBody, Canonicalization.CanonicalizationBody(email.Body, type), "body " + type);
			Assert.AreEqual(canonicalizedHeaders, Canonicalization.CanonicalizationHeaders(email.Headers, type, false, "A", "B"), "headers " + type);
		}
	}
}
