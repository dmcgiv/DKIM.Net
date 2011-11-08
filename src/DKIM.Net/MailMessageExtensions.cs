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
using System.Linq.Expressions;
using System.Net.Mail;
using System.Reflection;
using JetBrains.Annotations;


namespace DKIM
{


	public static class MailMessageExtensions
	{

	    private static readonly Func<Stream, object> MailWriterFactory;
	    private static readonly Action<MailMessage, object, bool, bool> Send;
        private static readonly Action<object> Close;

		static MailMessageExtensions()
		{

            var messageType = typeof(MailMessage);
            var mailWriterType = messageType.Assembly.GetType("System.Net.Mail.MailWriter");
            

            // mail writer constructor
            {
                var constructorInfo = mailWriterType.GetConstructor(BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { typeof(Stream) }, null);
                var argument = Expression.Parameter(typeof(Stream), "arg");
                var conExp = Expression.New(constructorInfo, argument);
                MailWriterFactory = Expression.Lambda<Func<Stream, object>>(conExp, argument).Compile();
            }
            
            
            // mail message Send method
            {
                var sendMethod = messageType.GetMethod("Send", BindingFlags.Instance | BindingFlags.NonPublic);
                var mailWriter = Expression.Parameter(typeof(object), "mailWriter");
                var sendEnvelope = Expression.Parameter(typeof(bool), "sendEnvelope");
                var allowUnicode = Expression.Parameter(typeof(bool), "allowUnicode");
                var instance = Expression.Parameter(messageType, "instance");
                var call = Expression.Call(instance, sendMethod, Expression.Convert(mailWriter, mailWriterType), sendEnvelope, allowUnicode);

                Send = Expression.Lambda<Action<MailMessage, object, bool, bool>>(call, instance, mailWriter, sendEnvelope, allowUnicode).Compile();
            }


            // mail writer Close method
            {
                var closeMethod = mailWriterType.GetMethod("Close", BindingFlags.Instance | BindingFlags.NonPublic);
                var instance = Expression.Parameter(typeof(object), "instance");
                var call = Expression.Call(Expression.Convert(instance, mailWriterType), closeMethod);

                Close = Expression.Lambda<Action<object>>(call, instance).Compile();
            }



		}



        [NotNull]
        public static Email Parse([NotNull]this MailMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException("message");
            }

            return Email.Parse(GetText(message));
        }


		/// <summary>
		/// Converts the MailMessage entire email contents to a string.
		/// </summary>
        [NotNull]
        public static string GetText([NotNull]this MailMessage message)
		{
		    if (message == null)
		    {
		        throw new ArgumentNullException("message");
		    }

            if(message.From == null)
            {
                throw new ArgumentException("From property cannot be null");
            }

		    using (var internalStream = new ClosableMemoryStream())
			{
				
                object mailWriter = MailWriterFactory(internalStream);

			    Send(message, mailWriter, false, true);
			    Close(mailWriter);

				internalStream.Position = 0;
				string text;
				using (var reader = new StreamReader(internalStream))
				{
					text = reader.ReadToEnd();
				}

				internalStream.ReallyClose();

				return text;

			}
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

			if(email.Headers.ContainsKey("Content-Type"))
			{
				return !email.Headers["Content-Type"].Value.Trim()
					.StartsWith("multipart/alternative", StringComparison.InvariantCultureIgnoreCase);
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

            var email = Email.Parse(message.GetText());
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


            // get email content and generate initial signature
            var email = Email.Parse(message.GetText());
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

		/// <summary>
		/// Use memory stream with dummy Close method as MailWriter writes final CRLF when closing the stream. This allows us to read the stream and close it manually.
		/// </summary>
		class ClosableMemoryStream : MemoryStream
		{
		    public override void Close()
			{
                // do not close just yet
			}

			public void ReallyClose()
			{
				base.Close();
			}
		}

	}
}
