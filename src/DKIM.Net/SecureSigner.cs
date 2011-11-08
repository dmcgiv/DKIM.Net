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
using JetBrains.Annotations;


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
        [NotNull]
        byte[] Sign([NotNull]byte[] data, SigningAlgorithm algorithm);

        [NotNull]
        byte[] Hash([NotNull]byte[] data, SigningAlgorithm algorithm);
	}


	public class PrivateKeySigner : IPrivateKeySigner
	{

		#region Factory methods

        [NotNull]
		public static IPrivateKeySigner LoadFromFile([NotNull] string path)
		{
		    if (path == null)
		    {
		        throw new ArgumentNullException("path");
		    }

		    var privateKey = File.ReadAllText(path);

			return new PrivateKeySigner(privateKey);
		}

        [NotNull]
        public static IPrivateKeySigner Create([NotNull]string privateKey)
		{
			return new PrivateKeySigner(privateKey);
		}

		#endregion


		private readonly byte[] _key;


        private PrivateKeySigner([NotNull]string privateKey)
		{
			if (privateKey == null)
			{
				throw new ArgumentNullException("privateKey");
			}

			_key = OpenSslKey.DecodeOpenSSLPrivateKey(privateKey);

		}




		public byte[] Sign(byte[] data, SigningAlgorithm algorithm)
		{
		    if (data == null)
		    {
		        throw new ArgumentNullException("data");
		    }

		    using (var rsa = OpenSslKey.DecodeRSAPrivateKey(_key))
			{
				byte[] signature = rsa.SignData(data, GetHashName(algorithm));

				return signature;

			}
		}

	    public byte[] Hash(byte[] data, SigningAlgorithm algorithm)
	    {
	        if (data == null)
	        {
	            throw new ArgumentNullException("data");
	        }

	        using(var hash = GetHash(algorithm))
			{
				return hash.ComputeHash(data);	
			}
	    }


        [NotNull]
	    private static string GetHashName(SigningAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case SigningAlgorithm.RSASha1:
					{
						return "SHA1";
					}
				case SigningAlgorithm.RSASha256:
					{
						return "SHA256";
					}
				default:
					{
						throw new ArgumentException("Invalid SigningAlgorithm value", "algorithm");
					}

			}
		}

		private static HashAlgorithm GetHash(SigningAlgorithm algorithm)
		{
			switch (algorithm)
			{
				case SigningAlgorithm.RSASha1:
					{
						return new SHA1Managed();
					}
				case SigningAlgorithm.RSASha256:
					{
						return new SHA256Managed();
					}

				default:
					{
						throw new ArgumentException("Invalid SigningAlgorithm value", "algorithm");
					}

			}
		}
	}
}
