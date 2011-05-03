/*
 * Based on code found at:
 * http://neildeadman.wordpress.com/2011/02/01/amazon-simple-email-service-example-in-c-sendrawemail/
 * http://stackoverflow.com/questions/2423617/save-system-net-mail-mailmessage-as-msg-file
 * http://www.codeproject.com/KB/IP/smtpclientext.aspx
 * 
 * 
 * */
using System.IO;
using System.Net.Mail;
using System.Reflection;



namespace McGiv.DKIM
{

	/// <summary>
	/// Conterts a MailMessage entire contents to a string or byte array.
	/// </summary>
	public static class MailMessageData
	{
		
		private static readonly ConstructorInfo _mailWriterContructor;
		private static readonly MethodInfo _sendMethod;
		private static readonly MethodInfo _closeMethod;

		

		static MailMessageData()
		{
			// todo create empression trees to call instead of the method info objects.
			var t = typeof(MailMessage);

			Assembly assembly = t.Assembly;

			var mailWriterType = assembly.GetType("System.Net.Mail.MailWriter");

			_mailWriterContructor = mailWriterType.GetConstructor(
					BindingFlags.Instance | BindingFlags.NonPublic, null, new[] { typeof(Stream) }, null);

			_sendMethod = typeof(MailMessage).GetMethod("Send", BindingFlags.Instance | BindingFlags.NonPublic);

			_closeMethod = mailWriterType.GetMethod("Close", BindingFlags.Instance | BindingFlags.NonPublic);


		

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


		public static string GetText(this MailMessage message)
		{
			using (var internalStream = new ClosableMemoryStream())
			{
				object mailWriter = _mailWriterContructor.Invoke(new object[] { internalStream });

				_sendMethod.Invoke(message, BindingFlags.Instance | BindingFlags.NonPublic, null, new[] {mailWriter, true}, null);
				_closeMethod.Invoke(mailWriter, BindingFlags.Instance | BindingFlags.NonPublic, null, new object[] {}, null);

				internalStream.Position = 0;
				using(var reader = new StreamReader(internalStream))
				{
					return reader.ReadToEnd();
				}
				
			}
		}


	}
}
