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
	

	public class DkimSigner
	{


		/// <summary>
		/// Header key used to add DKIM information to email.
		/// </summary>
		public const string SignatureKey = "DKIM-Signature";


		private readonly IPrivateKeySigner _privateKeySigner;

		/// <summary>
		/// The domain that will be signing the email.
		/// </summary>
		private readonly string _domain;

		/// <summary>
		/// The selector used to obtain the public key.
		/// see http://www.dkim.org/info/dkim-faq.html#technical
		/// </summary>
		private readonly string _selector;


		/// <summary>
		/// Be careful what headers you sign. Ensure that they are not changed by your SMTP server or relay.
		/// If a header if changed after signing DKIM will fail.
		/// </summary>
		private readonly string[] _headersToSign;


		public DkimSigner(IPrivateKeySigner privateKeySigner, string domain, string selector, string[] headersToSign = null)
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


			_privateKeySigner = privateKeySigner;
			_domain = domain;
			_selector = selector;
			_headersToSign = headersToSign;


			this.Encoding = Encoding.UTF8;

		}

		
		// todo remove once stable.
		public IDebug Debug { get; set; }

		/// <summary>
		/// The encoding of the email.
		/// </summary>
		public Encoding Encoding { get; set; }

		public DkimCanonicalizationAlgorithm HeaderCanonicalization { get; set; }
		public DkimCanonicalizationAlgorithm BodyCanonicalization { get; set; }
		
		

		public MailMessage SignMessage(MailMessage message)
		{

			message.BodyEncoding = this.Encoding;
			message.SubjectEncoding = this.Encoding;
			




			// get email content and generate initial signature
			var email = Email.Parse(message);
			var value = this.GenerateDkimHeaderValue(email);

			

			// signature value get formatted so add dummy signature value then remove it
			message.Headers.Prepend(SignatureKey, value + new string('0', 70));
			email = Email.Parse(message);
			var formattedSig = email.Headers[SignatureKey].Value;
			email.Headers[SignatureKey].Value = formattedSig.Substring(0, formattedSig.Length - 70);



			// sign email
			value += GenerateSignature(email);
			message.Headers.Set(SignatureKey, value);


			return message;
		}


	

		/*
		 * see http://www.dkim.org/specs/rfc4871-dkimbase.html#dkim-sig-hdr
		 * 
		 * */
		public string GenerateDkimHeaderValue(Email email)
		{
			// timestamp  - seconds since 00:00:00 on January 1, 1970 UTC
			TimeSpan t = DateTime.Now.ToUniversalTime() -
						 DateTime.SpecifyKind(DateTime.Parse("00:00:00 January 1, 1970"), DateTimeKind.Utc);


			var signatureValue = new StringBuilder();

			var start = /*Email.NewLine + */" ";
			var end = ";";
			//nl= string.Empty;

			signatureValue.Append("v=1;");
			


			// algorithm used
			signatureValue.Append(start);
			signatureValue.Append("a=");
			signatureValue.Append(_privateKeySigner.Algorithm);
			signatureValue.Append(end);


		

			// Canonicalization
			signatureValue.Append(start);
			signatureValue.Append("c=");
			signatureValue.Append(this.HeaderCanonicalization.ToString().ToLower());
			signatureValue.Append('/');
			signatureValue.Append(this.BodyCanonicalization.ToString().ToLower());
			signatureValue.Append(end);


			// signing domain
			signatureValue.Append(start);
			signatureValue.Append("d=");
			signatureValue.Append(_domain);
			signatureValue.Append(end);



			// headers to be signed
			signatureValue.Append(start);
			signatureValue.Append("h=");
			foreach (var header in _headersToSign)
			{
				signatureValue.Append(header);
				signatureValue.Append(':');
			}
			signatureValue.Length--;
			signatureValue.Append(end);



			// i=identity
			// not supported


			// l=body length
			//not supported



			// public key location
			signatureValue.Append(start);
			signatureValue.Append("q=dns/txt");
			signatureValue.Append(end);



			

			// selector
			signatureValue.Append(start);
			signatureValue.Append("s=");
			signatureValue.Append(_selector);
			signatureValue.Append(end);


			// time sent
			signatureValue.Append(start);
			signatureValue.Append("t=");
			signatureValue.Append((int)t.TotalSeconds);
			signatureValue.Append(end);


			// x=expiration
			// not supported






			// hash of body
			signatureValue.Append(start);
			signatureValue.Append("bh=");
			signatureValue.Append(SignBody(email.Body));
			signatureValue.Append(end);


			// x=copied header fields
			// not supported



			signatureValue.Append(start);
			signatureValue.Append("b=");
			



			return signatureValue.ToString();
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="email">The email to sign.</param>
		/// <param name="signature"></param>
		/// <returns></returns>
		public string GenerateSignature(Email email)
		{


			var headers = DkimCanonicalizer.CanonicalizeHeaders(email.Headers, this.HeaderCanonicalization, true, _headersToSign);

			if (this.Debug != null)
			{
				this.Debug.WriteContent("DKIM signature", email.Headers[SignatureKey].Value);
				this.Debug.WriteContent("DKIM canonicalized headers", headers);

			}

			

			// assumes signature ends with "b="
			//return signature +  Convert.ToBase64String(_privateKeySigner.Sign(this.Encoding.GetBytes(headers)));
			return Convert.ToBase64String(_privateKeySigner.Sign(this.Encoding.GetBytes(headers)));


			

		}


		public string SignBody(string body)
		{
			var cb = DkimCanonicalizer.CanonicalizeBody(body, this.BodyCanonicalization);

			if (this.Debug != null)
			{
				this.Debug.WriteContent("DKIM body", body);
				this.Debug.WriteContent("DKIM canonicalized body", cb);
			}

			return Convert.ToBase64String(_privateKeySigner.Hash(Encoding.GetBytes(cb)));

		}



	}
}
