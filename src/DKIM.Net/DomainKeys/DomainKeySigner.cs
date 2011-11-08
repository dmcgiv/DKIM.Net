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
	

	public class DomainKeySigner : IEmailSigner
	{
		/// <summary>
		/// Header key used to add DKIM information to email.
		/// </summary>
		public const string SignatureKey = "DomainKey-Signature";


        #region Fields

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

        #endregion Fields

        #region Properties

        [NotNull]
        private Encoding _encoding = Encoding.UTF8;

        [PublicAPI]
	    [NotNull]
		public Encoding Encoding
	    {
	        get { return _encoding; }
	        set
	        {
                if(value == null)
                {
                    throw new ArgumentNullException("value");
                }

                // todo - check what encoding type can be supported
	            _encoding = value;
	        }
	    }


        /// <summary>
        /// The canonicalization algorithm used
        /// </summary>
        [PublicAPI]
	    public DomainKeyCanonicalizationAlgorithm Canonicalization { get; set; }
		
        //// todo remove once stable.
        //public IDebug Debug { get; set; }

        #endregion Properties


        public DomainKeySigner([NotNull]IPrivateKeySigner privateKeySigner, [NotNull]string domain, [NotNull]string selector, string[] headersToSign)
		{
			if (privateKeySigner == null)
			{
				throw new ArgumentNullException("privateKeySigner");
			}

			if (domain == null)
			{
				throw new ArgumentNullException("domain");
			}

            if(domain.Length == 0)
            {
                throw new ArgumentException("Domain cannot be an empty string.");
            }

			if (selector == null)
			{
				throw new ArgumentNullException("selector");
			}

            if (selector.Length == 0)
            {
                throw new ArgumentException("Selector cannot be an empty string.");
            }


			_domain = domain;
			_selector = selector;
			_headersToSign = headersToSign;
			_privateKeySigner = privateKeySigner;

			this.Encoding = Encoding.UTF8;
		}




		public string SignEmail(string text)
		{
	
			var email = Email.Parse(text);
			var sig = this.GenerateSignature(email);

			return SignatureKey + ':' + sig + Email.NewLine + email.Raw;

		}


        [PublicAPI]
        [NotNull]
	    public string GenerateSignature([NotNull]Email email)
		{

			var signatureValue = new StringBuilder();

			const string start = Email.NewLine + " ";
			const string end = ";";

			// algorithm used
			signatureValue.Append(start);
			signatureValue.Append("a=");
			signatureValue.Append("rsa-sha1");// only rsa-sha1 suprted
			signatureValue.Append(end);


			// Canonicalization
			signatureValue.Append(start);
			signatureValue.Append("c=");
			signatureValue.Append(this.Canonicalization.ToString().ToLower());
			signatureValue.Append(end);


			// signing domain
			signatureValue.Append(start);
			signatureValue.Append("d=");
			signatureValue.Append(_domain);
			signatureValue.Append(end);


			// headers to be signed
			if (_headersToSign != null && _headersToSign.Length > 0)
			{
				signatureValue.Append(start);
				signatureValue.Append("h=");
				foreach (var header in _headersToSign)
				{
					signatureValue.Append(header);
					signatureValue.Append(':');
				}
				signatureValue.Length--;
				signatureValue.Append(end);
			}


			// public key location
			signatureValue.Append(start);
			signatureValue.Append("q=dns");
			signatureValue.Append(end);

			// selector
			signatureValue.Append(start);
			signatureValue.Append("s=");
			signatureValue.Append(_selector);
			signatureValue.Append(end);


			// signature data
			signatureValue.Append(start);
			signatureValue.Append("b=");
	
			signatureValue.Append(SignSignature(email));
			signatureValue.Append(end);

			return signatureValue.ToString();
		}


        [PublicAPI]
        [NotNull]
        public string SignSignature([NotNull]Email email)
        {

            var text = DomainKeyCanonicalizer.Canonicalize(email, this.Canonicalization, _headersToSign);

            //if (this.Debug != null)
            //{
            //    this.Debug.WriteContent("DomainKey canonicalized headers", text);
            //}

            return Convert.ToBase64String(_privateKeySigner.Sign(this.Encoding.GetBytes(text), SigningAlgorithm.RSASha1));

        }
	}
}
