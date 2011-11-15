using System.Configuration;
using System.Net.Mail;
using NUnit.Framework;

namespace DKIM.Tests
{

    [TestFixture]
    public class MailMessageSendTests
    {
        private readonly string _from, _to, _domain, _selector, _privateKey;


        public MailMessageSendTests()
        {
            _from = ConfigurationManager.AppSettings["SenderEmail"];
            _to = ConfigurationManager.AppSettings["RecipientEmail"];

            _domain = ConfigurationManager.AppSettings["domain"];
            _selector = ConfigurationManager.AppSettings["selector"];

            _privateKey = ConfigurationManager.AppSettings["privatekey"];
        }



        [Test]
        public void Valid_send_sign_DKIM()
        {

            var msg = new MailMessage();
            msg.To.Add(new MailAddress(_to, "Jim Bob"));
            msg.From = new MailAddress(_from, "Joe Bloggs");
            msg.Subject = "Test DKIM Message";
            msg.Body = "A simple message";


            var dkimSigner = new DkimSigner(PrivateKeySigner.Create(_privateKey), _domain, _selector);

            msg.DkimSign(dkimSigner);

            var smtp = new SmtpClient();

            smtp.Send(msg);



        }



        [Test]
        public void Valid_send_sign_DomainKey()
        {

            var msg = new MailMessage();
            msg.To.Add(new MailAddress(_to, "Jim Bob"));
            msg.From = new MailAddress(_from, "Joe Bloggs");
            msg.Subject = "Test DomainKeys Message";
            msg.Body = "A simple message";


            var domainKeySigner = new DomainKeySigner(PrivateKeySigner.Create(_privateKey), _domain, _selector);

            msg.DomainKeySign(domainKeySigner);

            var smtp = new SmtpClient();

            smtp.Send(msg);



        }


        [Test]
        public void Valid_send_sign_DKIM_then_DomainKey()
        {
            var msg = new MailMessage();
            msg.To.Add(new MailAddress(_to, "Jim Bob"));
            msg.From = new MailAddress(_from, "Joe Bloggs");
            msg.Subject = "Test DKIM & DOmainKeys Message";
            msg.Body = "A simple message";


            var dkimSigner = new DkimSigner(PrivateKeySigner.Create(_privateKey), _domain, _selector);

            msg.DkimSign(dkimSigner);


            var domainKeySigner = new DomainKeySigner(PrivateKeySigner.Create(_privateKey), _domain, _selector);

            msg.DomainKeySign(domainKeySigner);

            var smtp = new SmtpClient();

            smtp.Send(msg);
        }


        [Test]
        public void Valid_send_sign_DomainKey_then_DKIM()
        {
            var msg = new MailMessage();
            msg.To.Add(new MailAddress(_to, "Jim Bob"));
            msg.From = new MailAddress(_from, "Joe Bloggs");
            msg.Subject = "Test DOmainKeys and DKIM Message";
            msg.Body = "A simple message";



            var domainKeySigner = new DomainKeySigner(PrivateKeySigner.Create(_privateKey), _domain, _selector);

            msg.DomainKeySign(domainKeySigner);


            var dkimSigner = new DkimSigner(PrivateKeySigner.Create(_privateKey), _domain, _selector);

            msg.DkimSign(dkimSigner);




            var smtp = new SmtpClient();

            smtp.Send(msg);
        }
    }
}
