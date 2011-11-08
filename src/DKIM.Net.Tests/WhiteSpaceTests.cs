using NUnit.Framework;

namespace DKIM.Tests
{

    [TestFixture]
    public class WhiteSpaceTests
    {
        [TestCase(' ', true)]
        [TestCase('\t', true)]
        [TestCase('\n', true)]
        [TestCase('\r', true)]
        [TestCase('a', false)]
        [TestCase('1', false)]
        [TestCase('*', false)]
        public void IsWhiteSpace(char c, bool isWhiteSpace)
        {
            Assert.AreEqual(isWhiteSpace, c.IsWhiteSpace());
        }


        [TestCase("  a     b    c  ", " a b c")]
        [TestCase(@"      a      


     b   

c    

", " a b c")]
        public void ReduceWhiteSpace(string text, string reduced)
        {
            Assert.AreEqual(reduced, text.ReduceWitespace());
        }

        [TestCase("  a     b    c  ", "abc")]
        [TestCase(@"      a      


     b   

c    

", "abc")]
        public void RemoveWhiteSpace(string text, string reduced)
        {
            Assert.AreEqual(reduced, text.RemoveWhitespace());
        }

    }
}
