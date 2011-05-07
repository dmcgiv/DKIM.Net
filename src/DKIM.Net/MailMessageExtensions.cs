/*
 * DKIM.Net
 * 
 * Copyright (C) 2011 Damien McGivern, damien@mcgiv.com
 * 
 * 
 * 
 * */
using System.Collections.Specialized;
using System.IO;
using System.Net.Mail;
using System.Reflection;



namespace DKIM
{

	
	public static class MailMessageExtensions
	{

		private static readonly ConstructorInfo MailWriterContructor;
		private static readonly MethodInfo SendMethod;
		private static readonly MethodInfo CloseMethod;

		private static readonly FieldInfo MsgField;
		private static readonly PropertyInfo HeadersProperty;

		static MailMessageExtensions()
		{
			// todo create empression trees to call instead of the method info objects.
			var messageType = typeof(MailMessage);

			Assembly assembly = messageType.Assembly;


			// internal mail writer
			var mailWriterType = assembly.GetType("System.Net.Mail.MailWriter");

			MailWriterContructor = mailWriterType.GetConstructor(
					BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { typeof(Stream) }, null);

			SendMethod = typeof(MailMessage).GetMethod("Send", BindingFlags.Instance | BindingFlags.NonPublic);

			CloseMethod = mailWriterType.GetMethod("Close", BindingFlags.Instance | BindingFlags.NonPublic);



			// internal message object
			var innerMsgType = messageType.Assembly.GetType("System.Net.Mail.Message");

			MsgField = messageType.GetField("message", BindingFlags.NonPublic | BindingFlags.Instance);

			HeadersProperty = innerMsgType.GetProperty("EnvelopeHeaders", BindingFlags.NonPublic | BindingFlags.Instance);
			


		}



		/// <summary>
		/// Converts the MailMessage entire email contents to a string.
		/// </summary>
		public static string GetText(this MailMessage message)
		{
			using (var internalStream = new ClosableMemoryStream())
			{
				object mailWriter = MailWriterContructor.Invoke(new object[] { internalStream });

				SendMethod.Invoke(message,  new[] {mailWriter, false});
				CloseMethod.Invoke(mailWriter, new object[] {});

				internalStream.Position = 0;
				string text;
				using(var reader = new StreamReader(internalStream))
				{
					text = reader.ReadToEnd();
				}

				internalStream.ReallyClose();

				return text;

			}
		}



		public static void PrependHeader(this MailMessage message, bool useEnvelope, string key, string value)
		{
		
			var msg = MsgField.GetValue(message);

			var headers = (NameValueCollection) HeadersProperty.GetValue(msg, null);

			if (useEnvelope)
			{
				headers.Prepend(key, value);
			}
			else
			{
				message.Headers.Prepend(key, value);
			}


		}
		/// <summary>
		/// Use memory stream with dummy Close method as MailWriter writes final CRLF when closing the stream. This allows us to read the stream and close it manually.
		/// </summary>
		class ClosableMemoryStream : MemoryStream
		{
			public override void Close()
			{

			}

			public void ReallyClose()
			{
				base.Close();
			}
		}

	}
}
