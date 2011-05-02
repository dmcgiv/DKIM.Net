﻿using System;
using System.Collections.Generic;
using System.IO;


namespace McGiv.DKIM
{

	/// <summary>
	/// Stores the origional header key and value and wether or not the value is folded.
	/// </summary>
	public class EmailHeader
	{
		public string Key;
		public string Value;

		/// <summary>
		/// Indicates that the value is folded over multiple lines.
		/// </summary>
		public bool FoldedValue;
	}


	public class Email
	{
		public Dictionary<string, EmailHeader> Headers { get; private set; }
		public string Body { get; private set; }

		Email()
		{
			
		}

		public const string NewLine = "\r\n";

		


		public static Email Parse(byte[] data)
		{
			return Parse(new StreamReader(new MemoryStream(data)));
		}

		public static Email Parse(string data)
		{
			return Parse(new StringReader(data));
		}

		static Email Parse(TextReader reader)
		{
			
			var headers = new Dictionary<string, EmailHeader>(StringComparer.InvariantCultureIgnoreCase);
			using (reader)
			{
				string line;
				string lastKey = null;
				while ((line = reader.ReadLine()) != null)
				{

					if (line == string.Empty)
					{
						// end of headers
						return new Email { Headers = headers, Body = reader.ReadToEnd() };
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

			return new Email { Headers = headers, Body = string.Empty };


		}
	}
}