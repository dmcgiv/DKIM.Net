DKIM.Net
===========
DomainKeys Identified Mail (DKIM) and Domain Key email signing for .Net Framework


Known Issues
------------
As System.Net.Mail.SmtpClient generates boundary identifiers randomly and as this code hacks the SmtpClient to retrieve the full email 
content before sending the code cannot be used when sending with SmtpClient and the MailMessage when the MailMessage has an alternative view or an attachment.
	
	



Example - Sending with SmtpClient
------------
```c#
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
``` 
 
Example - DNS Records
-----------------------

Domain Key settings

	_domainkey "o=~;r=admin@mydomain.com"
	
Domain Key / DKIM selector

	selector._domainkey "k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDetWmczoNly/wfDc5WH8F2o42kGjYG7bbmfxjNP2y2qZja84v5W8z8SL702w3N5ZwQLdQmuQ8yN4WOYrg8DHGOB6g+xVP3h1Hr1+C05Vk/x3BXw0wIffNqcVzPkRNNNILtiwPJhhlDVMvaTx20vrrCAz9i6CX6Onj4OWxUaAjtuQIDAQAB"
