/*
 * DKIM.Net
 * 
 * Copyright (C) 2011 Damien McGivern, damien@mcgiv.com
 * 
 * 
 * 
 * */
using System;
using System.IO;
using System.Security.Cryptography;


namespace DKIM
{

	/// <summary>
	/// The algorithms supported
	/// </summary>
	// ReSharper disable InconsistentNaming
	public enum SigningAlgorithm
	{
		/// <summary>
		/// Supported by DKIM and DomainKeys
		/// </summary>
		RSASha1,


		/// <summary>
		/// Supported by DKIM
		/// </summary>
		RSASha256

	}
	// ReSharper restore InconsistentNaming


	public interface IPrivateKeySigner
	{
		byte[] Sign(byte[] data);
		byte[] Hash(byte[] data);
		string Algorithm { get;  }
	}


	public class AlgorithmInfo
	{
		public AlgorithmInfo(SigningAlgorithm algorithm)
		{
			this.SigningAlgorithm = algorithm;

			switch (algorithm)
			{
				case SigningAlgorithm.RSASha1:
					{
						this.HashAlgorithm = new SHA1Managed();
						this.Name = "rsa-sha1";

						break;
					}
				case SigningAlgorithm.RSASha256:
					{
						this.HashAlgorithm = new SHA256Managed();
						this.Name = "rsa-sha256";

						break;
					}

				default:
					{
						throw new ArgumentException("Invalid SigningAlgorithm value", "algorithm");
					}

			}
		}

		public SigningAlgorithm SigningAlgorithm { get; private set; }
		public HashAlgorithm HashAlgorithm { get; private set; }
		public string Name { get; private set; }

	}

	public class PrivateKeySigner : IPrivateKeySigner
	{

		#region Factory methods
		
		public static IPrivateKeySigner LoadFromFile(string path, SigningAlgorithm signingAlgorithm = SigningAlgorithm.RSASha256)
		{
			var privateKey = File.ReadAllText(path);

			return new PrivateKeySigner(privateKey, signingAlgorithm);
		}


		public static IPrivateKeySigner Create(string privateKey, SigningAlgorithm signingAlgorithm = SigningAlgorithm.RSASha256)
		{
			return new PrivateKeySigner(privateKey, signingAlgorithm);
		}

		#endregion


		private readonly byte[] _key;
		private readonly AlgorithmInfo _algorithmInfo;

		PrivateKeySigner(string privateKey, SigningAlgorithm signingAlgorithm)
		{
			if (privateKey == null)
			{
				throw new ArgumentNullException("privateKey");
			}

			_key = OpenSslKey.DecodeOpenSSLPrivateKey(privateKey);

			_algorithmInfo = new AlgorithmInfo(signingAlgorithm);
		}



		public byte[] Sign(byte[] data)
		{

			using (var rsa = OpenSslKey.DecodeRSAPrivateKey(_key))
			{
				byte[] signature = rsa.SignData(data, _algorithmInfo.SigningAlgorithm == SigningAlgorithm.RSASha1 ? "SHA1" : "SHA256");
				
				return signature;

			}
			
		}

		public byte[] Hash(byte[] data)
		{
			return _algorithmInfo.HashAlgorithm.ComputeHash(data);
		}

		public string Algorithm
		{
			get { return _algorithmInfo.Name; }
		}


		
	}
}
