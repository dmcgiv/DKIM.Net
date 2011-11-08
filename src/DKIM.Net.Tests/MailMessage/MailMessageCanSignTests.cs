using System.IO;
using System.Net.Mail;
using System.Net.Mime;
using System.Reflection;
using NUnit.Framework;

namespace DKIM.Tests
{

    [TestFixture]
    public class MailMessageCanSignTests
    {

        [Test]
        public void Can_sign()
        {
            var msg = new MailMessage("from@domain.com", "to@domain.com", "subject", "body");

            //Console.WriteLine(msg.GetText());

            Assert.IsTrue(msg.CanSign());

        }

        [Test]
        public void Cannot_sign_multiple_alt_views()
        {
            var msg = new MailMessage("from@domain.com", "to@domain.com", "subject", "body");

            var htmlView = AlternateView.CreateAlternateViewFromString("<p>some html</p>", new ContentType(@"text/html"));
            msg.AlternateViews.Add(htmlView);
            
            //Console.WriteLine(msg.GetText());

            Assert.IsFalse(msg.CanSign());

        }

        [Test]
        public void Cannot_sign_attachment()
        {
            var msg = new MailMessage("from@domain.com", "to@domain.com", "subject", "body");

            var path = Path.GetDirectoryName( Assembly.GetExecutingAssembly().Location) + @"\MailMessage\Attachment.htm";
            var attachment = new Attachment(path, new ContentType(@"text/html"));
            msg.Attachments.Add(attachment);

            //Console.WriteLine(msg.GetText());
            Assert.IsFalse(msg.CanSign());

        }
    }
}
