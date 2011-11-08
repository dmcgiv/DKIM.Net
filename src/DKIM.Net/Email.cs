/*
 * DKIM.Net
 * 
 * Copyright (C) 2011 Damien McGivern, damien@mcgiv.com
 * 
 * 
 * 
 * */
using System;
using System.Collections.Generic;
using System.IO;
using JetBrains.Annotations;


namespace DKIM
{

    /// <summary>
    /// Repersents an email message. Used during the signing process.
    /// </summary>
	public class Email
	{
		public Dictionary<string, EmailHeader> Headers { get; private set; }
		public string Body { get; private set; }
		public string Raw { get; private set; }

		Email()
		{
			
		}

		public const string NewLine = "\r\n";


        [NotNull]
        public static Email Parse([NotNull]string data)
		{
	        if (data == null)
	        {
	            throw new ArgumentNullException("data");
	        }


	        var headers = new Dictionary<string, EmailHeader>(StringComparer.InvariantCultureIgnoreCase);
			using (var reader = new StringReader(data))
			{
				
				string line;
				string lastKey = null;

                // process headers
				while ((line = reader.ReadLine()) != null)
				{

					if (line == string.Empty)
					{
						// end of headers
						return new Email { Headers = headers, Body = reader.ReadToEnd(), Raw = data };
					}


					// check for folded value
					if (lastKey != null && line.Length > 0 && line[0].IsWhiteSpace())
					{
						var header = headers[lastKey];
						header.FoldedValue = true;
						header.Value += Email.NewLine + line;
						
						continue;
					}


					// parse key & value 
					int sep = line.IndexOf(':');

					if (sep == -1)
					{
						throw new FormatException("Expected seperator not found in line." + line);
					}

					var key = line.Substring(0, sep);
					var value = line.Substring(sep + 1);
					lastKey = key.Trim().ToLower();

					
					headers.Add(lastKey, new EmailHeader { Key = key, Value = value });



				}
			}

            // email must have no body
			return new Email { Headers = headers, Body = string.Empty, Raw = data};


		}
	}
}
