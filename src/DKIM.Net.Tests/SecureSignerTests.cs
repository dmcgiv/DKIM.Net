using System.Configuration;
using System.Text;
using NUnit.Framework;

namespace McGiv.DKIM.Tests
{
	[TestFixture]
	public class SecureSignerTests
	{

		[Test]
		public void Check()
		{
			var data = Encoding.Unicode.GetBytes("this is the test text");


			var bc = new BouncyCastlePrivateKeySigner(ConfigurationManager.AppSettings["privatekey"]);

			var bcSign = bc.Sign(data);



			var win = new OpenSslKeyPrivateKeySigner(ConfigurationManager.AppSettings["privatekey"]);

			var winSign = win.Sign(data);


			Assert.AreEqual(bcSign, winSign);
		}



	
	}
}
