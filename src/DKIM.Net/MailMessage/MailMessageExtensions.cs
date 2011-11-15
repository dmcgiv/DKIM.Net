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
using JetBrains.Annotations;


namespace DKIM
{


	public static class MailMessageExtensions
	{



        /// <summary>
        /// Parse a MailMessage content into an Email object.
        /// </summary>
        [NotNull]
        public static Email Parse([NotNull]this MailMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            return Email.Parse(message.GetText());
        }





        //public static void PrependHeader([NotNull]this MailMessage message, bool useEnvelope, [NotNull]string key, [NotNull]string value)
        //{
        //    if (message == null)
        //    {
        //        throw new ArgumentNullException("message");
        //    }

        //    var msg = MsgField.GetValue(message);

        //    var headers = (NameValueCollection)HeadersProperty.GetValue(msg, null);

        //    if (useEnvelope)
        //    {
        //        headers.Prepend(key, value);
        //    }
        //    else
        //    {
        //        message.Headers.Prepend(key, value);
        //    }


        //}


		/// <summary>
		/// Indicates if the library is able to sign the given MailMessage
		/// </summary>
		/// <param name="message"></param>
		/// <returns></returns>
        public static bool CanSign([NotNull]this MailMessage message)
		{
			// the signing process for mail messages involves 'sending' it multiple times
			// to an in memory stream instead of an SMTP server. Unfortunately every time 
			// the message is sent the boundary header value is regenerated meaning the signing is broken.
			// Boundaries are used with mulit part emails e.g. adding attachments or including a text and html version
			if (message == null)
			{
				throw new ArgumentNullException("message");
			}

			var email = Email.Parse(message.GetText());

		    return CanSign(email);

		}


        private static bool CanSign([NotNull] Email email)
        {

            if (email.Headers.ContainsKey("Content-Type"))
            {
                // fails for:
                // multipart/alternative
                // multipart/mixed

                return !email.Headers["Content-Type"].Value.Trim()
                    .StartsWith("multipart/", StringComparison.InvariantCultureIgnoreCase);
            }

            return true;
        }


        [NotNull]
        public static MailMessage DomainKeySign([NotNull]this MailMessage message, DomainKeySigner signer)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            if (signer == null)
            {
                throw new ArgumentNullException("signer");
            }

            message.BodyEncoding = signer.Encoding;
            message.SubjectEncoding = signer.Encoding;
            message.HeadersEncoding = signer.Encoding;

            var email = Email.Parse(message.GetText());

            if(!CanSign(email))
            {
                throw new InvalidOperationException("Unable to Domain Key sign the message");
            }

            var sig = signer.GenerateSignature(email);

            message.Headers.Prepend(DomainKeySigner.SignatureKey, sig);

            return message;
        }


        [NotNull]
        public static MailMessage DkimSign([NotNull]this MailMessage message, DkimSigner signer)
        {

            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            if (signer == null)
            {
                throw new ArgumentNullException("signer");
            }

            message.BodyEncoding = signer.Encoding;
            message.SubjectEncoding = signer.Encoding;
            message.HeadersEncoding = signer.Encoding;


            // get email content and generate initial signature
            var email = Email.Parse(message.GetText());

            if (!CanSign(email))
            {
                throw new InvalidOperationException("Unable to Domain Key sign the message");
            }

            var value = signer.GenerateDkimHeaderValue(email);



            // signature value get formatted so add dummy signature value then remove it
            message.Headers.Prepend(DkimSigner.SignatureKey, value + new string('0', 70));
            email = message.Parse();
            var formattedSig = email.Headers[DkimSigner.SignatureKey].Value;
            email.Headers[DkimSigner.SignatureKey].Value = formattedSig.Substring(0, formattedSig.Length - 70);



            // sign email
            value += signer.GenerateSignature(email);
            message.Headers.Set(DkimSigner.SignatureKey, value);


            return message;
        }
	}
}
