//**********************************************************************************
//
//OpenSSLKey
// .NET 2.0  OpenSSL Public & Private Key Parser
//
// Copyright (C) 2008  	JavaScience Consulting
//
//***********************************************************************************
//
//  opensslkey.cs
//
//  Reads and parses:
//    (1) OpenSSL PEM or DER public keys
//    (2) OpenSSL PEM or DER traditional SSLeay private keys (encrypted and unencrypted)
//    (3) PKCS #8 PEM or DER encoded private keys (encrypted and unencrypted)
//  Keys in PEM format must have headers/footers .
//  Encrypted Private Key in SSLEay format not supported in DER
//  Removes header/footer lines.
//  For traditional SSLEAY PEM private keys, checks for encrypted format and
//  uses PBE to extract 3DES key.
//  For SSLEAY format, only supports encryption format: DES-EDE3-CBC
//  For PKCS #8, only supports PKCS#5 v2.0  3des.
//  Parses private and public key components and returns .NET RSA object.
//  Creates dummy unsigned certificate linked to private keypair and
//  optionally exports to pkcs #12
//
// See also: 
//  http://www.openssl.org/docs/crypto/pem.html#PEM_ENCRYPTION_FORMAT 
//**************************************************************************************

/* see http://www.jensign.com/opensslkey/opensslkey.cs */

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DKIM
{
	internal static class OpenSslKey
	{
		private static int GetIntegerSize(BinaryReader binr)
		{
			byte bt = 0;
			byte lowbyte = 0x00;
			byte highbyte = 0x00;
			int count = 0;
			bt = binr.ReadByte();
			if (bt != 0x02)		//expect integer
				return 0;
			bt = binr.ReadByte();

			if (bt == 0x81)
				count = binr.ReadByte();	// data size in next byte
			else
				if (bt == 0x82)
				{
					highbyte = binr.ReadByte();	// data size in next 2 bytes
					lowbyte = binr.ReadByte();
					byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
					count = BitConverter.ToInt32(modint, 0);
				}
				else
				{
					count = bt;		// we already have the data size
				}



			while (binr.ReadByte() == 0x00)
			{	//remove high order zeros in data
				count -= 1;
			}
			binr.BaseStream.Seek(-1, SeekOrigin.Current);		//last ReadByte wasn't a removed zero, so back up a byte
			return count;
		}

		public static RSACryptoServiceProvider DecodeRSAPrivateKey(byte[] privkey)
		{
			byte[] MODULUS, E, D, P, Q, DP, DQ, IQ;

			// ---------  Set up stream to decode the asn.1 encoded RSA private key  ------
			var mem = new MemoryStream(privkey);
			var binr = new BinaryReader(mem);    //wrap Memory Stream with BinaryReader for easy reading
			byte bt = 0;
			ushort twobytes = 0;
			int elems = 0;
			try
			{
				twobytes = binr.ReadUInt16();
				if (twobytes == 0x8130)	//data read as little endian order (actual data order for Sequence is 30 81)
					binr.ReadByte();	//advance 1 byte
				else if (twobytes == 0x8230)
					binr.ReadInt16();	//advance 2 bytes
				else
					return null;

				twobytes = binr.ReadUInt16();
				if (twobytes != 0x0102)	//version number
					return null;
				bt = binr.ReadByte();
				if (bt != 0x00)
					return null;


				//------  all private key components are Integer sequences ----
				elems = GetIntegerSize(binr);
				MODULUS = binr.ReadBytes(elems);

				elems = GetIntegerSize(binr);
				E = binr.ReadBytes(elems);

				elems = GetIntegerSize(binr);
				D = binr.ReadBytes(elems);

				elems = GetIntegerSize(binr);
				P = binr.ReadBytes(elems);

				elems = GetIntegerSize(binr);
				Q = binr.ReadBytes(elems);

				elems = GetIntegerSize(binr);
				DP = binr.ReadBytes(elems);

				elems = GetIntegerSize(binr);
				DQ = binr.ReadBytes(elems);

				elems = GetIntegerSize(binr);
				IQ = binr.ReadBytes(elems);

				


				// ------- create RSACryptoServiceProvider instance and initialize with public key -----
				var RSA = new RSACryptoServiceProvider();
				var RSAparams = new RSAParameters
				                	{
				                		Modulus = MODULUS,
				                		Exponent = E,
				                		D = D,
				                		P = P,
				                		Q = Q,
				                		DP = DP,
				                		DQ = DQ,
				                		InverseQ = IQ
				                	};
				RSA.ImportParameters(RSAparams);
				return RSA;
			}
			catch (Exception)
			{
				return null;
			}
			finally { binr.Close(); }
		}


		//-----  Get the binary RSA PRIVATE key, decrypting if necessary ----
		public static byte[] DecodeOpenSSLPrivateKey(String instr)
		{
			const string pemprivheader = "-----BEGIN RSA PRIVATE KEY-----";
			const string pemprivfooter = "-----END RSA PRIVATE KEY-----";
			string pemstr = instr.Trim();
			if (!pemstr.StartsWith(pemprivheader) || !pemstr.EndsWith(pemprivfooter))
				return null;

			var sb = new StringBuilder(pemstr);
			sb.Replace(pemprivheader, "");  //remove headers/footers, if present
			sb.Replace(pemprivfooter, "");

			string pvkstr = sb.ToString().Trim();	//get string after removing leading/trailing whitespace

			try
			{
				// if there are no PEM encryption info lines, this is an UNencrypted PEM private key
				return Convert.FromBase64String(pvkstr);
			}
			catch (System.FormatException e)
			{		//if can't b64 decode, it must be an encrypted private key
				throw new FormatException("Not an unencrypted OpenSSL PEM private key", e);
			}


		}
	}
}
