using System;
using System.Configuration;
using System.Net.Mail;
using NUnit.Framework;

namespace McGiv.DKIM.Tests
{

	[TestFixture]
	public class MailMessageTests
	{


		[Test]
		public void SendSignedEmail()
		{
			var message = new MailMessage();


			message.To.Add(new MailAddress("check-auth@verifier.port25.com", "Port25"));

			message.From = new MailAddress(ConfigurationManager.AppSettings["from"]);

			// message contains white space 
			message.Body = @"this is a test
sdfsd     fs
dfs  
    df
sdf


sd  fsdf


";
			message.Subject = "hi planet";
			message.IsBodyHtml = false;




			var dkim = new DKIMSigner(
				PrivateKeySigner.Create(ConfigurationManager.AppSettings["privatekey"]),
				ConfigurationManager.AppSettings["domain"],
				ConfigurationManager.AppSettings["selector"],
				new string[] { "From", "To", "Subject" }
				);



			//dkim.Debug = new ConsoleDebug();



			var signedMessage = dkim.SignMessage(message);


			new SmtpClient().Send(signedMessage);

		}
	}
}
