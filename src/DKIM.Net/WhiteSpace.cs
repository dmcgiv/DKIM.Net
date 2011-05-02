using System.Text;

namespace McGiv.DKIM
{
	public static class WhiteSpace
	{


		public static bool IsWhiteSpace(this char c)
		{
			return c == ' ' || c == '\t';
		}



		/// <summary>
		/// Reduces all adjacent white space characters to a single space character.
		/// </summary>
		/// <param name="text"></param>
		/// <returns></returns>
		public static string ReduceWitespace(this string text)
		{
			if (text.IndexOfAny(new char[] { ' ', '\t' }) == -1)
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
	}
}
