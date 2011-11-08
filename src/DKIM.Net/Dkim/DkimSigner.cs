/*
 * DKIM.Net
 * 
 * Copyright (C) 2011 Damien McGivern, damien@mcgiv.com
 * 
 * 
 * 
 * */
using System;
using System.Text;
using JetBrains.Annotations;

namespace DKIM
{


	public class DkimSigner : IEmailSigner
	{


		/// <summary>
		/// Header key used to add DKIM information to email.
		/// </summary>
		public const string SignatureKey = "DKIM-Signature";


		private readonly IPrivateKeySigner _privateKeySigner;

        private Encoding _encoding;

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


        public DkimSigner([NotNull]IPrivateKeySigner privateKeySigner, [NotNull]string domain, [NotNull]string selector, string[] headersToSign = null)
		{
			if (privateKeySigner == null)
			{
				throw new ArgumentNullException("privateKeySigner");
			}

			if (domain == null)
			{
				throw new ArgumentNullException("domain");
			}

			if (domain.Length == 0)
			{
				throw new ArgumentException("Cannot be empty.", "domain");
			}

			if (selector == null)
			{
				throw new ArgumentNullException("selector");
			}

			if(selector.Length == 0)
			{
				throw new ArgumentException("Cannot be empty.", "selector");
			}


			_privateKeySigner = privateKeySigner;
			_domain = domain;
			_selector = selector;
			_headersToSign = headersToSign;


			this.Encoding = Encoding.UTF8;

		}

		
		// todo remove once stable.
        //public IDebug Debug { get; set; }

	    

	    /// <summary>
		/// The encoding of the email.
		/// </summary>
		public Encoding Encoding
	    {
	        get { return _encoding; }
	        set
	        {
	            if(value == null)
	            {
	                throw new ArgumentNullException("value");
	            }
                _encoding = value;
	        }
	    }

        /// <summary>
        /// The algorithm used to sign the email
        /// </summary>
	    public SigningAlgorithm SigningAlgorithm { get; set; }


        /// <summary>
        /// The canonicalization algorithm used for the headers of the email
        /// </summary>
		public DkimCanonicalizationAlgorithm HeaderCanonicalization { get; set; }


        /// <summary>
        /// The canonicalization algorithm used for the body of the email
        /// </summary>
		public DkimCanonicalizationAlgorithm BodyCanonicalization { get; set; }






        public string SignEmail(string message)
		{

            // get email content and generate initial signature
			var email = Email.Parse(message);
			

			email.Headers.Add(SignatureKey, new EmailHeader { Key = SignatureKey, Value = this.GenerateDkimHeaderValue(email) });
			
			email.Headers[SignatureKey].Value += this.GenerateSignature(email);

			return SignatureKey + ':' + email.Headers[SignatureKey].Value + Email.NewLine + email.Raw;
	
		}





		private string GetAlgorithmName()
		{
			switch(this.SigningAlgorithm)
			{
				case DKIM.SigningAlgorithm.RSASha1:
					{
						return "rsa-sha1";
					}
				case DKIM.SigningAlgorithm.RSASha256:
					{
						return "rsa-sha256";
					}
				default:
					{
						throw new InvalidOperationException("Invalid SigningAlgorithm");
					}
			}
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

			const string start = Email.NewLine + " ";
			const string end = ";";
			

			signatureValue.Append("v=1;");
			


			// algorithm used
			signatureValue.Append(start);
			signatureValue.Append("a=");
			signatureValue.Append(GetAlgorithmName());
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
		/// <returns></returns>
		public string GenerateSignature([NotNull] Email email)
		{
		    if (email == null)
		    {
		        throw new ArgumentNullException("email");
		    }

            if (email.Headers == null)
            {
                throw new ArgumentException("email headers property is null");
            }

		    var headers = DkimCanonicalizer.CanonicalizeHeaders(email.Headers, this.HeaderCanonicalization, true, _headersToSign);

            //if (this.Debug != null)
            //{
            //    this.Debug.WriteContent("DKIM signature", email.Headers[SignatureKey].Value);
            //    this.Debug.WriteContent("DKIM canonicalized headers", headers);

            //}

			

			// assumes signature ends with "b="
			return Convert.ToBase64String(_privateKeySigner.Sign(this.Encoding.GetBytes(headers), this.SigningAlgorithm));

			
		}


		public string SignBody(string body)
		{

			var cb = DkimCanonicalizer.CanonicalizeBody(body, this.BodyCanonicalization);

            //if (this.Debug != null)
            //{
            //    this.Debug.WriteContent("DKIM body", body);
            //    this.Debug.WriteContent("DKIM canonicalized body", cb);
            //}

			return Convert.ToBase64String(_privateKeySigner.Hash(Encoding.GetBytes(cb), this.SigningAlgorithm));

		}



	}
}
