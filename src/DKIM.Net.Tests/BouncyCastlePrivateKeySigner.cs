using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace McGiv.DKIM.Tests
{
	/*
	 * old secure signer - used to test new one
	 * 
	 * */
	public class BouncyCastlePrivateKeySigner : IPrivateKeySigner
	{
		private readonly string _privateKey;


		public BouncyCastlePrivateKeySigner(string privateKey)
		{
			this._privateKey = privateKey;
		}



		public byte[] Sign(byte[] data)
		{
			using (var reader = new StringReader(_privateKey))
			{
				var r = new PemReader(reader);
				var o = (AsymmetricCipherKeyPair)r.ReadObject();

				ISigner sig = SignerUtilities.GetSigner("SHA256WithRSAEncryption");
				sig.Init(true, o.Private);
				sig.BlockUpdate(data, 0, data.Length);

				return sig.GenerateSignature();
			}
		}
	}

}
