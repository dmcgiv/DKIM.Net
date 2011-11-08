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
	public interface IEmailSigner
	{
        [NotNull]
        string SignEmail([NotNull]string text);
		//MailMessage SignMailMessage(MailMessage message);
	}


	public class EmailSigner : IEmailSigner
	{
		private readonly IEmailSigner _dkimSigner; 
		private readonly IEmailSigner _domainKeySigner ;

		public EmailSigner(IEmailSigner domainKeySigner, IEmailSigner dkimSigner)
		{
			_domainKeySigner = domainKeySigner;
			_dkimSigner = dkimSigner;
		}

		public string SignEmail(string text)
		{
			// best to sige with DKIM first as domain keys signer may be configured to sign entire email text
			// and so will fail if the text is signed by DKIM afterwards
			if (_dkimSigner != null)
			{
				text = _dkimSigner.SignEmail(text);
			}

			if (_domainKeySigner != null)
			{
				text = _domainKeySigner.SignEmail(text);
			}

			return text;
		}
	}

	public class FullEmailSigner : IEmailSigner
	{
		private readonly IEmailSigner _dkimSigner;
		private readonly IEmailSigner _domainKeySigner;

		public FullEmailSigner(
            [NotNull] IPrivateKeySigner privateKey, 
            [NotNull] Encoding encoding, 
            [NotNull] string domain, 
            [NotNull] string dkimSelector, 
            [NotNull] string domainKeySelector, 
            [NotNull] string[] headers)
		{
		    if (privateKey == null) throw new ArgumentNullException("privateKey");
		    if (encoding == null) throw new ArgumentNullException("encoding");
		    if (domain == null) throw new ArgumentNullException("domain");
		    if (dkimSelector == null) throw new ArgumentNullException("dkimSelector");
		    if (domainKeySelector == null) throw new ArgumentNullException("domainKeySelector");
		    if (headers == null) throw new ArgumentNullException("headers");


		    var dkim = new DkimSigner(
				privateKey,
				domain,
				dkimSelector,
				headers
				);




			//var debugger = new ConsoleDebug();

			//dkim.Debug = debugger;

			dkim.Encoding = encoding;
			dkim.BodyCanonicalization = DkimCanonicalizationAlgorithm.Simple;

			_dkimSigner = dkim;


			var domainKeySigner = new DomainKeySigner(
				privateKey,
				domain,
				domainKeySelector,
				headers
				);

			domainKeySigner.Encoding = encoding;
			domainKeySigner.Canonicalization = DomainKeyCanonicalizationAlgorithm.Nofws;
			
			_domainKeySigner = domainKeySigner;

		}
		public string SignEmail(string text)
		{
			text = _dkimSigner.SignEmail(text);
			return _domainKeySigner.SignEmail(text);

		}
	}
}
