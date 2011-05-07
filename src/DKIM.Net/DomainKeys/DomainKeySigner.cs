/*
 * DKIM.Net
 * 
 * Copyright (C) 2011 Damien McGivern, damien@mcgiv.com
 * 
 * 
 * 
 * */
using System;
using System.Net.Mail;
using System.Text;

namespace DKIM
{
	public class DomainKeySigner
	{
		/// <summary>
		/// Header key used to add DKIM information to email.
		/// </summary>
		public const string SignatureKey = "DomainKey-Signature";


		private readonly IPrivateKeySigner _privateKeySigner;


		/// <summary>
		/// The domain that will be signing the email.
		/// </summary>
		private readonly string _domain;

		/// <summary>
		/// The selector used to obtain the public key.
		/// </summary>
		private readonly string _selector;


		/// <summary>
		/// Be careful what headers you sign. Ensure that they are not changed by your SMTP server or relay.
		/// If a header if changed after signing DKIM will fail.
		/// </summary>
		private readonly string[] _headersToSign;

		public Encoding Encoding { get; set; }
		public DomainKeyCanonicalizationAlgorithm Canonicalization { get; set; }


		public DomainKeySigner(IPrivateKeySigner privateKeySigner, string domain, string selector, string[] headersToSign)
		{
			if (privateKeySigner == null)
			{
				throw new ArgumentNullException("privateKeySigner");
			}

			if (domain == null)
			{
				throw new ArgumentNullException("domain");
			}

			if (selector == null)
			{
				throw new ArgumentNullException("selector");
			}


			_domain = domain;
			_selector = selector;
			_headersToSign = headersToSign;
			_privateKeySigner = privateKeySigner;

			this.Encoding = Encoding.UTF8;
		}


		public MailMessage SignMessage(MailMessage message)
		{

			message.BodyEncoding = this.Encoding;
			message.SubjectEncoding = this.Encoding;
			



			
			var email = Email.Parse(message);
			var sig = this.GenerateSignature(email);

			
			message.Headers.Prepend(SignatureKey, sig);
			

			

			return message;
		}
	

		public string GenerateSignature(Email email)
		{


			Console.WriteLine();
			Console.WriteLine("-- org start ---");
			Console.Write(email.Origional);
			Console.WriteLine("-- org end ---");

			var signatureValue = new StringBuilder();

			var nl = Email.NewLine + " ";
			nl = string.Empty;





			// algorithm used
			signatureValue.Append(nl);
			signatureValue.Append("a=");
			signatureValue.Append(_privateKeySigner.Algorithm);
			signatureValue.Append("; ");





			// Canonicalization
			signatureValue.Append(nl);
			signatureValue.Append("c=");
			signatureValue.Append(this.Canonicalization.ToString().ToLower());
			signatureValue.Append("; ");


			// signing domain
			signatureValue.Append(nl);
			signatureValue.Append("d=");
			signatureValue.Append(_domain);
			signatureValue.Append("; ");


			// headers to be signed
			if (_headersToSign != null && _headersToSign.Length > 0)
			{
				signatureValue.Append(nl);
				signatureValue.Append("h=");
				foreach (var header in _headersToSign)
				{
					signatureValue.Append(header);
					signatureValue.Append(':');
				}
				signatureValue.Length--;
				signatureValue.Append("; ");
			}



			// public key location
			signatureValue.Append(nl);
			signatureValue.Append("q=dns; ");



		


			// selector
			signatureValue.Append(nl);
			signatureValue.Append("s=");
			signatureValue.Append(_selector);
			signatureValue.Append("; ");


			// signature data

			signatureValue.Append(nl);
			signatureValue.Append("b=");
			signatureValue.Append(SignSignature(email));
			signatureValue.Append(";");

			return signatureValue.ToString();
		}


		public string SignSignature(Email email)
		{

			var text = DomainKeyCanonicalizer.Canonicalize(email, this.Canonicalization, _headersToSign);

			Console.WriteLine();
			Console.WriteLine("-- start ---");
			Console.Write(text);
			Console.WriteLine("-- end ---");

			return Convert.ToBase64String(_privateKeySigner.Sign(this.Encoding.GetBytes(text)));

		}
	}
}
