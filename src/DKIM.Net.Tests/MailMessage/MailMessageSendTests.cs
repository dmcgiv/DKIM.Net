using System.Configuration;
using System.Net.Mail;
using NUnit.Framework;

namespace DKIM.Tests
{


    /// <summary>
    /// tests sending signed MailMessage emails 
    /// tested with yahoo and gmail addresses and both pass
    /// </summary>
    [TestFixture]
    public class MailMessageSendTests
    {
        private readonly string _from, _to, _domain, _selector, _privateKey;


        public MailMessageSendTests()
        {
            _from = ConfigurationManager.AppSettings["from"];
            _to = ConfigurationManager.AppSettings["to"];

            _domain = ConfigurationManager.AppSettings["domain"];
            _selector = ConfigurationManager.AppSettings["selector"];

            _privateKey = ConfigurationManager.AppSettings["privatekey"];
        }

        static string[] GetHeaders(string headers)
        {
            return headers == null ? null : headers.Split(',');
        }


        [TestCase(null)]
        [TestCase("From,To,Subject")]
        public void Valid_send_sign_DKIM(string headers)
        {

            var msg = new MailMessage();
            msg.To.Add(new MailAddress(_to, "Jim Bob"));
            msg.From = new MailAddress(_from, "Joe Bloggs");
            msg.Subject = "Test DKIM Message";
            msg.Body = "A simple message";


            var dkimSigner = new DkimSigner(PrivateKeySigner.Create(_privateKey), _domain, _selector, GetHeaders(headers));

            msg.DkimSign(dkimSigner);

            var smtp = new SmtpClient();

            smtp.Send(msg);



        }



        [TestCase(null)]
        [TestCase("From,To,Subject")]
        public void Valid_send_sign_DomainKey(string headers)
        {

            var msg = new MailMessage();
            msg.To.Add(new MailAddress(_to, "Jim Bob"));
            msg.From = new MailAddress(_from, "Joe Bloggs");
            msg.Subject = "Test DomainKeys Message";
            msg.Body = "A simple message";


            var domainKeySigner = new DomainKeySigner(PrivateKeySigner.Create(_privateKey), _domain, _selector, GetHeaders(headers));

            msg.DomainKeySign(domainKeySigner);

            var smtp = new SmtpClient();

            smtp.Send(msg);



        }


        [TestCase(null)]
        [TestCase("From,To,Subject")]
        public void Valid_send_sign_DKIM_then_DomainKey(string headers)
        {
            var msg = new MailMessage();
            msg.To.Add(new MailAddress(_to, "Jim Bob"));
            msg.From = new MailAddress(_from, "Joe Bloggs");
            msg.Subject = "Test DKIM & DomainKeys Message";
            msg.Body = "A simple message";


            var dkimSigner = new DkimSigner(PrivateKeySigner.Create(_privateKey), _domain, _selector, GetHeaders(headers));

            msg.DkimSign(dkimSigner);


            var domainKeySigner = new DomainKeySigner(PrivateKeySigner.Create(_privateKey), _domain, _selector, GetHeaders(headers));

            msg.DomainKeySign(domainKeySigner);

            var smtp = new SmtpClient();

            smtp.Send(msg);
        }


        [TestCase(null)]
        [TestCase("From,To,Subject")]
        public void Valid_send_sign_DomainKey_then_DKIM(string headers)
        {
            var msg = new MailMessage();
            msg.To.Add(new MailAddress(_to, "Jim Bob"));
            msg.From = new MailAddress(_from, "Joe Bloggs");
            msg.Subject = "Test DomainKeys & DKIM Message";
            msg.Body = "A simple message";



            var domainKeySigner = new DomainKeySigner(PrivateKeySigner.Create(_privateKey), _domain, _selector, GetHeaders(headers));

            msg.DomainKeySign(domainKeySigner);


            var dkimSigner = new DkimSigner(PrivateKeySigner.Create(_privateKey), _domain, _selector, GetHeaders(headers));

            msg.DkimSign(dkimSigner);




            var smtp = new SmtpClient();

            smtp.Send(msg);
        }
    }
}
