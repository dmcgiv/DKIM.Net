using System;
using System.Configuration;
using System.Net.Mail;
using System.Text;
using NUnit.Framework;

namespace DKIM.Tests
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
			message.Body = @"abc©
 ©   ©
 ©


";
			message.Subject = @"test©";
			message.IsBodyHtml = false;



			var privateKey = PrivateKeySigner.Create(ConfigurationManager.AppSettings["privatekey"], SigningAlgorithm.RSASha1);

			var dkim = new DkimSigner(
				privateKey,
				ConfigurationManager.AppSettings["domain"],
				ConfigurationManager.AppSettings["selector"],
				new string[] { "From", "To", "Subject" }
				);



			var debugger = new ConsoleDebug();

			dkim.Debug = debugger;



			var domainkey = new DomainKeySigner(
				privateKey, 
				ConfigurationManager.AppSettings["domain"],
				ConfigurationManager.AppSettings["selector"], 
				new string[] { "From", "To", "Subject" }
				);

			

			var signedMessage = dkim.SignMessage(message);

			
			var text = signedMessage.GetText();
			debugger.WriteLine();
			debugger.WriteContent("dkim", text);


			signedMessage = domainkey.SignMessage(signedMessage);
			
			text = signedMessage.GetText();
			debugger.WriteContent("domainkey", text);

			new SmtpClient().Send(signedMessage);

		}
	}
}
