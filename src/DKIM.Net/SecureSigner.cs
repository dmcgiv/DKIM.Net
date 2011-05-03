using System;
using System.IO;


namespace McGiv.DKIM
{
	public interface IPrivateKeySigner
	{
		byte[] Sign(byte[] data);
	}


	public class PrivateKeySigner : IPrivateKeySigner
	{

		public static IPrivateKeySigner LoadFromFile(string path)
		{
			var privateKey = File.ReadAllText(path);

			return new PrivateKeySigner(privateKey);
		}


		public static IPrivateKeySigner Create(string privateKey)
		{
			return new PrivateKeySigner(privateKey);
		}


		private readonly byte[] _key;


		PrivateKeySigner(string privateKey)
		{
			if (privateKey == null)
			{
				throw new ArgumentNullException("privateKey");
			}

			_key = OpenSslKey.DecodeOpenSSLPrivateKey(privateKey);
		}



		public byte[] Sign(byte[] data)
		{

			using (var rsa = OpenSslKey.DecodeRSAPrivateKey(_key))
			{
				byte[] signature = rsa.SignData(data, "SHA256");
				
				return signature;

			}
			
		}


	}
}
