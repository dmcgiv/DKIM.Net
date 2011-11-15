using System;
using System.IO;
using System.Linq.Expressions;
using System.Net.Mail;
using System.Reflection;
using JetBrains.Annotations;

namespace DKIM
{
    public static class MailMessageText
    {
        private static readonly Func<Stream, object> MailWriterFactory;
        private static readonly Action<MailMessage, object, bool, bool> Send3;
        private static readonly Action<MailMessage, object, bool> Send2;
        private static readonly Action<object> Close;

        static MailMessageText()
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
            // void Send(BaseWriter writer, Boolean sendEnvelope)
            // void Send(BaseWriter writer, bool sendEnvelope, bool allowUnicode)
            {
                var sendMethod = messageType.GetMethod("Send", BindingFlags.Instance | BindingFlags.NonPublic);
                var mailWriter = Expression.Parameter(typeof(object), "mailWriter");
                var sendEnvelope = Expression.Parameter(typeof(bool), "sendEnvelope");
                var allowUnicode = Expression.Parameter(typeof(bool), "allowUnicode");
                var instance = Expression.Parameter(messageType, "instance");

                var pars = sendMethod.GetParameters();
                if (pars.Length == 3)
                {
                    var call = Expression.Call(instance, sendMethod, Expression.Convert(mailWriter, mailWriterType),
                                               sendEnvelope, allowUnicode);

                    Send3 =
                        Expression.Lambda<Action<MailMessage, object, bool, bool>>(call, instance, mailWriter,
                                                                                   sendEnvelope, allowUnicode).Compile();
                }
                else if (pars.Length == 2)
                {
                    var call = Expression.Call(instance, sendMethod, Expression.Convert(mailWriter, mailWriterType),
                                              sendEnvelope);

                    Send2 =
                        Expression.Lambda<Action<MailMessage, object, bool>>(call, instance, mailWriter,
                                                                                   sendEnvelope).Compile();
                }
            }


            // mail writer Close method
            {
                var closeMethod = mailWriterType.GetMethod("Close", BindingFlags.Instance | BindingFlags.NonPublic);
                var instance = Expression.Parameter(typeof(object), "instance");
                var call = Expression.Call(Expression.Convert(instance, mailWriterType), closeMethod);

                Close = Expression.Lambda<Action<object>>(call, instance).Compile();
            }



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

            if (message.From == null)
            {
                throw new ArgumentException("From property cannot be null");
            }

            using (var internalStream = new ClosableMemoryStream())
            {

                object mailWriter = MailWriterFactory(internalStream);

                if (Send2 != null)
                {
                    Send2(message, mailWriter, false);
                }
                else
                {
                    Send3(message, mailWriter, false, true);
                }

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


        /// <summary>
        /// Use memory stream with dummy Close method as MailWriter writes final CRLF when closing the stream. This allows us to read the stream and close it manually.
        /// </summary>
        private class ClosableMemoryStream : MemoryStream
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
