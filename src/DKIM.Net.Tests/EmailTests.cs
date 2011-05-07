using System;
using NUnit.Framework;

namespace DKIM.Tests
{

	[TestFixture]
	public class EmailTests
	{

		[Test]
		public void NewLine()
		{
			Assert.AreEqual(Environment.NewLine, Email.NewLine);
		}



		[Test]
		public void Test1()
		{

			var content = @"key1:Value1
Key2 : VALue2
Key3:Folded
 Value

start of email body
";

			var  email = Email.Parse(content);

			foreach (var h in email.Headers)
			{
				Console.WriteLine();
				Console.WriteLine("--- header start ---");
				Console.WriteLine(h.Key);
				Console.WriteLine(h.Value.Key);
				Console.WriteLine("folded : " + h.Value.FoldedValue);
				Console.WriteLine(h.Value.Value);
				Console.WriteLine("--- header end ---");
			}


			Console.WriteLine("--- body start ---");
			Console.WriteLine(email.Body);
			Console.WriteLine("--- body end ---");

		}
	}
}
