/*
 * DKIM.Net
 * 
 * Copyright (C) 2011 Damien McGivern, damien@mcgiv.com
 * 
 * 
 * 
 * */
using System;
using System.IO;
using System.Text;
using JetBrains.Annotations;

namespace DKIM
{
	public enum DomainKeyCanonicalizationAlgorithm
	{
		Simple,

		/// <summary>
		/// No Folding White Space
		/// </summary>
		Nofws
	}

	public static class DomainKeyCanonicalizer
	{
        [NotNull]
        public static string Canonicalize([NotNull] Email email, DomainKeyCanonicalizationAlgorithm algorithm, params string[] headersToSign)
		{
            if (email == null)
            {
                throw new ArgumentNullException("email");
            }

            Func<String, string> process;
			switch (algorithm)
			{
				case DomainKeyCanonicalizationAlgorithm.Simple:
					{
						process = x => x;
						break;
					}
				case DomainKeyCanonicalizationAlgorithm.Nofws:
					{
                        process = x => (x == null) ? null : x.RemoveWhitespace();
						break;
					}
				default:
					{
						throw new ArgumentException("Invalid canonicalization type.");
					}
			}


			var headers = new StringBuilder();

			if (headersToSign == null || headersToSign.Length == 0)
			{

				foreach (var h in email.Headers)
				{
					headers.Append(process(h.Value.Key));
					headers.Append(':');
					headers.AppendLine(process(h.Value.Value));
				}

			}
			else
			{
				foreach (string key in headersToSign)
				{
                    if(key == null)
                    {
                        continue;
                    }

					if (!email.Headers.ContainsKey(key))
					{
						continue;
					}
					var h = email.Headers[key];

					headers.Append(process(h.Key));
					headers.Append(':');
					headers.AppendLine(process(h.Value));
				}
			}

			var body = new StringBuilder();
			using (var reader = new StringReader(email.Body ?? string.Empty))
			{
				string line;
				int emptyLines = 0;

				// if only empty lines don't write until these is text after them
				while ((line = reader.ReadLine()) != null)
				{
					if (line.Length == 0)
					{
						emptyLines++;
					}
					else
					{
						while (emptyLines > 0)
						{
							body.AppendLine();
							emptyLines--;
						}

						body.AppendLine(process(line));

					}

				}
			}


			// If the body consists entirely of empty lines, then the header/body
			// line is similarly ignored.
			if (body.Length == 0)
			{
				return headers.ToString();
			}


			return headers
				.AppendLine() // header/body seperator line
				.Append(body).ToString();
		}
	}
}
