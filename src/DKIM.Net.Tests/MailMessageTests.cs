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

			message.Subject = @"test©";
			// message contains white space 
//            message.Body = @"abc©
// ©   ©
// ©
//
//
//";

//            message.IsBodyHtml = false;


//            message.Body = @"
//line 1
//
//line 2
//
//line 3";


			message.AlternateViews.Add(AlternateView.CreateAlternateViewFromString("text", Encoding.ASCII, "text/plain"));
			message.AlternateViews.Add(AlternateView.CreateAlternateViewFromString("html", Encoding.ASCII, "text/html"));



			var privateKey = PrivateKeySigner.Create(ConfigurationManager.AppSettings["privatekey"], SigningAlgorithm.RSASha1);

			var dkim = new DkimSigner(
				privateKey,
				ConfigurationManager.AppSettings["domain"],
				ConfigurationManager.AppSettings["selector"],
				new string[] { "From", "To", "Subject" }
				);



			var debugger = new ConsoleDebug();

			dkim.Debug = debugger;
			dkim.Encoding = Encoding.ASCII;
			dkim.BodyCanonicalization = DkimCanonicalizationAlgorithm.Relaxed;



	

			

			var signedMessage = dkim.SignMessage(message);

			
			var text = signedMessage.GetText();
			debugger.WriteLine();
			debugger.WriteContent("dkim", text);



		//    var domainkey = new DomainKeySigner(
		//privateKey,
		//ConfigurationManager.AppSettings["domain"],
		//ConfigurationManager.AppSettings["selector"],
		//new string[] { "From", "To", "Subject" }
		//);

			//signedMessage = domainkey.SignMessage(signedMessage);
			
			//text = signedMessage.GetText();
			//debugger.WriteContent("domainkey", text);

			new SmtpClient().Send(signedMessage);

		}
	}
}
