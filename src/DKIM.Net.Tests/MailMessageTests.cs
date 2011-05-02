using System;
using System.Configuration;
using System.Net.Mail;
using NUnit.Framework;

namespace McGiv.DKIM.Tests
{

	[TestFixture]
	public class MailMessageTests
	{
		readonly DKIMSigner _signer;

		public MailMessageTests()
		{
			_signer = new DKIMSigner();


			_signer.Encoding = System.Text.Encoding.ASCII;

			_signer.BodyCanonicalization = CanonicalizationAlgorithm.Relaxed;
			//_signer.HeaderCanonicalization = CanonicalizationAlgorithm.Relaxed;

			_signer.Debug = new ConsoleDebug();

			
			_signer.HeadersToSign = new string[] { "From", "To", "Subject" };




			_signer.PrivateKey = ConfigurationManager.AppSettings["privatekey"];
			_signer.Domain = ConfigurationManager.AppSettings["domain"];
			_signer.Selector = ConfigurationManager.AppSettings["selector"];

		}





		[Test]
		public void Test1()
		{
			var message = new MailMessage();

			//message.To.Add(new MailAddress( "damien@mcgiv.com", "Damien McGivern"));
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


			var signedMessage = _signer.SignMessage(message);

			Console.WriteLine(signedMessage.Headers[DKIMSigner.DKIMSignatureKey]);


			new SmtpClient().Send(signedMessage);

		}
	}
}
