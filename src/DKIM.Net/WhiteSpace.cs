/*
 * DKIM.Net
 * 
 * Copyright (C) 2011 Damien McGivern, damien@mcgiv.com
 * 
 * 
 * 
 * */
using System.Text;

namespace DKIM
{
	public static class WhiteSpace
	{


		public static bool IsWhiteSpace(this char c)
		{
			return c == ' ' || c == '\t' || c == '\r' || c == '\n';
		}



		/// <summary>
		/// Reduces all adjacent white space characters to a single space character.
		/// </summary>
		/// <param name="text"></param>
		/// <returns></returns>
		public static string ReduceWitespace(this string text)
		{
			if (text.IndexOfAny(new char[] { ' ', '\t', '\r', '\n' }) == -1)
			{
				return text;
			}

			var sb = new StringBuilder();
			bool hasWhiteSpace = false;
			foreach (var c in text)
			{
				if (c.IsWhiteSpace())
				{
					hasWhiteSpace = true;
				}
				else
				{
					if (hasWhiteSpace)
					{
						sb.Append(' ');
					}
					sb.Append(c);
					hasWhiteSpace = false;
				}


			}

			return sb.ToString();

		}



		/// <summary>
		/// Removes all white space characters from a line of text
		/// </summary>
		/// <param name="text"></param>
		/// <returns></returns>
		public static string RemoveWhitespace(this string text)
		{
			if (text.IndexOfAny(new char[] { ' ', '\t', '\r', '\n' }) == -1)
			{
				return text;
			}

			var sb = new StringBuilder();
			foreach (var c in text)
			{
				switch(c)
				{
					case ' ':
					case '\t':
					case '\r':
					case '\n':
						{
							break;
						}
					default:
						{
							sb.Append(c);
							break;
						}
				}
				
			}

			return sb.ToString();
		}
	}
}
