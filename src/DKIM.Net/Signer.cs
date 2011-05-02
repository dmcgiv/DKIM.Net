using System;
using System.IO;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace McGiv.DKIM
{
	

	public class DKIMSigner
	{
		

		public DKIMSigner()
		{
			// default should be simple but simple header canonicalization is currently not working :(
			HeaderCanonicalization = CanonicalizationAlgorithm.Relaxed;
		}

		/// <summary>
		/// The selector used to obtain the public key.
		/// see http://www.dkim.org/info/dkim-faq.html#technical
		/// </summary>
		public string Selector { get; set; }


		/// <summary>
		/// The domain that will be signing the email.
		/// </summary>
		public string Domain { get; set; }


		// todo remove once stable.
		public IDebug Debug { get; set; }

		/// <summary>
		/// The private key used to sign the email.
		/// </summary>
		public string PrivateKey { get; set; }


		/// <summary>
		/// The encoding of the email.
		/// </summary>
		public Encoding Encoding { get; set; }



		/// <summary>
		/// Be careful what headers you sign. Ensure that they are not changed by your SMTP server or relay.
		/// If a header if changed after signing DKIM will fail.
		/// </summary>
		public string[] HeadersToSign { get; set; }

		public CanonicalizationAlgorithm HeaderCanonicalization { get; private set; } // todo change setter to public once simple working
		public CanonicalizationAlgorithm BodyCanonicalization { get; set; }

		private readonly HashAlgorithm _hashAlgorithm = new SHA256Managed();




		/// <summary>
		/// Header key used to add DKIM information to email.
		/// </summary>
		public const string DKIMSignatureKey = "DKIM-Signature";

		public MailMessage SignMessage(MailMessage message)
		{

			message.BodyEncoding = this.Encoding;
			message.SubjectEncoding = this.Encoding;
			


			message.Headers.Add(DKIMSignatureKey, " ");


			// get email content and generate initial signature
			var data = MailMessageData.GetBytes(message);
			var email = Email.Parse(data);
			var sig = this.GenerateSignature(email);

			message.Headers.Set(DKIMSignatureKey, sig);

			// get updated email content and update signature with the signed signature
			data = MailMessageData.GetBytes(message);
			email = Email.Parse(data);
			sig = this.SignSignature(email, sig);

			message.Headers.Set(DKIMSignatureKey, sig);


			

			return message;
		}


		public string SignBody(string body)
		{

			return Convert.ToBase64String(_hashAlgorithm.ComputeHash(Encoding.GetBytes(body)));

		}

		/*
		 * see http://www.dkim.org/specs/rfc4871-dkimbase.html#dkim-sig-hdr
		 * 
		 * */
		public string GenerateSignature(Email email)
		{
			// timestamp  - seconds since 00:00:00 on January 1, 1970 UTC
			TimeSpan t = DateTime.Now.ToUniversalTime() -
						 DateTime.SpecifyKind(DateTime.Parse("00:00:00 January 1, 1970"), DateTimeKind.Utc);


			var signatureValue = new StringBuilder();

			var nl = Email.NewLine + " ";
			nl= string.Empty;

			signatureValue.Append("v=1; ");
			


			// algorithm used
			signatureValue.Append(nl);
			signatureValue.Append("a=rsa-sha256; ");
			

			// Canonicalization
			signatureValue.Append(nl);
			signatureValue.Append("c=");
			signatureValue.Append(this.HeaderCanonicalization.ToString().ToLower());
			signatureValue.Append('/');
			signatureValue.Append(this.BodyCanonicalization.ToString().ToLower());
			signatureValue.Append("; ");
			


			// public key location
			signatureValue.Append(nl);
			signatureValue.Append("q=dns/txt; ");
			


			// signing domain
			signatureValue.Append(nl);
			signatureValue.Append("d=");
			signatureValue.Append(this.Domain);
			signatureValue.Append("; ");
			

			// selector
			signatureValue.Append(nl);
			signatureValue.Append("s=");
			signatureValue.Append(this.Selector);
			signatureValue.Append("; ");


			// time sent
			signatureValue.Append(nl);
			signatureValue.Append("t=");
			signatureValue.Append((int)t.TotalSeconds);
			signatureValue.Append("; ");


			// hash of body
			signatureValue.Append(nl);
			signatureValue.Append("bh=");
			signatureValue.Append(SignBody(Canonicalization.CanonicalizationBody(email.Body, this.BodyCanonicalization)));
			signatureValue.Append("; ");

			// headers to be signed
			signatureValue.Append(nl);
			signatureValue.Append("h=");
			foreach (var header in this.HeadersToSign)
			{
				signatureValue.Append(header);
				signatureValue.Append(':');
			}
			signatureValue.Length--;
			signatureValue.Append("; ");


			signatureValue.Append(nl);
			signatureValue.Append("b=");


			return signatureValue.ToString();
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="email">The email to sign.</param>
		/// <param name="signature"></param>
		/// <returns></returns>
		public string SignSignature(Email email, string signature)
		{


			var headers = Canonicalization.CanonicalizationHeaders(email.Headers, this.HeaderCanonicalization, true, this.HeadersToSign);

			if (this.Debug != null)
			{
				this.Debug.WriteLine();
				this.Debug.WriteLine();
				this.Debug.WriteLine("---- Canonicalization Headers ----");
				this.Debug.WriteLine(headers);
				this.Debug.WriteLine("---- Canonicalization Headers ----");
			}


			using (TextReader reader = new StringReader(this.PrivateKey))
			{
				var r = new PemReader(reader);
				var o = (AsymmetricCipherKeyPair)r.ReadObject();
				byte[] plaintext = this.Encoding.GetBytes(headers);
				ISigner sig = SignerUtilities.GetSigner("SHA256WithRSAEncryption");
				sig.Init(true, o.Private);
				sig.BlockUpdate(plaintext, 0, plaintext.Length);
				
				// assumes signature ends with "b="
				return signature + Convert.ToBase64String(sig.GenerateSignature());
			}

			

		}






	}
}
