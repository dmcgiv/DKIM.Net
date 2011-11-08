using NUnit.Framework;

namespace DKIM.Tests.Dkim
{
	[TestFixture]
	public class Body
	{

		[TestCase(null, Email.NewLine, DkimCanonicalizationAlgorithm.Simple)]
		[TestCase("", Email.NewLine, DkimCanonicalizationAlgorithm.Simple)]
		[TestCase("a", "a" + Email.NewLine, DkimCanonicalizationAlgorithm.Simple)]
		[TestCase(@"a
b
c", @"a
b
c
", DkimCanonicalizationAlgorithm.Simple)]
		[TestCase(@"a

b

c
", @"a

b

c
", DkimCanonicalizationAlgorithm.Simple)]
		public void C(string orig, string expected, DkimCanonicalizationAlgorithm type)
		{
			Assert.AreEqual(expected, DkimCanonicalizer.CanonicalizeBody(orig, type));
		}
	}
}
