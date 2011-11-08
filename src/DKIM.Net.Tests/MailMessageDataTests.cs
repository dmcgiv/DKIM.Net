using System;
using System.Net.Mail;
using NUnit.Framework;

namespace DKIM.Tests
{

	[TestFixture]
	public class MailMessageDataTests
	{

		[Test]
		public void BasicEmail()
		{
			var msg = new MailMessage();
			msg.To.Add(new MailAddress("jb@domain.com", "Jim Bob"));
			msg.From = new MailAddress("joe.bloggs@domain.com", "Joe Bloggs");
			msg.Subject = "Test Message";
			msg.Body = "A simple message";
            
			var data = msg.GetText();


			Console.WriteLine(data);

		}
	}
}
