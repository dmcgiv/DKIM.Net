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


			
			//message.To.Add(new MailAddress("check-auth@verifier.port25.com", "Port25"));
			message.To.Add(new MailAddress("damien@mcgiv.com", "Damien McGivern"));


			message.From = new MailAddress(ConfigurationManager.AppSettings["from"]);

			// message contains white space 
			message.Body = @"abc©
 ©   ©
 ©


";
			message.Subject = @"test©";
			message.IsBodyHtml = false;



			var p = PrivateKeySigner.Create(ConfigurationManager.AppSettings["privatekey"], SigningAlgorithm.RSASha1);

			var dkim = new DkimSigner(
				p,
				ConfigurationManager.AppSettings["domain"],
				ConfigurationManager.AppSettings["selector"],
				new string[] { "From", "To", "Subject" }
				);



			var debugger = new ConsoleDebug();

			dkim.Debug = debugger;
			


			var dm = new DomainKeySigner(p, ConfigurationManager.AppSettings["domain"],
													ConfigurationManager.AppSettings["selector"], new string[] { "From", "To", "Subject"/*, "Content-Type", "Content-Transfer-Encoding"*/ });

			

			var signedMessage = dkim.SignMessage(message);

			// debug
			var text = signedMessage.GetText();
			debugger.WriteLine();
			debugger.WriteContent("dkim", text);
			// debug



			signedMessage = dm.SignMessage(signedMessage);
			
			// debug
			text = signedMessage.GetText();
			debugger.WriteContent("domainkey", text);
			// debug

			new SmtpClient().Send(signedMessage);

		}
	}
}
