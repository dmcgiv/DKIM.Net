DKIM.Net
===========
DomainKeys Identified Mail (DKIM) and Domain Key email signing for .Net Framework


Known Issues
------------
As System.Net.Mail.SmtpClient generates boundary identifiers randomly and this code hacks the SmtpClient to retrieve the full email content before sending email the code cannot be used when sending with SmtpClient and the MailMessage has an alternative view or attacgment.
	
	



Example - Sending with SmtpClient
------------

	var msg = new MailMessage();

	msg.From = new MailAddress("me@mydomain.com", "Joe Bloggs");
	msg.To.Add(new MailAddress("check-auth@verifier.port25.com", "Port25"));
	msg.Subject = "Testing DKIM.Net";
	msg.Body = "Hello World";
	
	
	
	
	var privateKey = PrivateKeySigner.Create(@"-----BEGIN RSA PRIVATE KEY-----
	....
	-----END RSA PRIVATE KEY-----");
	


	var domainKeySigner = new DomainKeySigner(privateKey, "mydomain.com", "abc", new string[] { "From", "To", "Subject" });
	msg.DomainKeySign(domainKeySigner);


	var dkimSigner = new DkimSigner(privateKey, "mydomain.com", "abc", new string[] { "From", "To", "Subject" });
	msg.DkimSign(dkimSigner);

	new SmtpClient().Send(msg);
 
