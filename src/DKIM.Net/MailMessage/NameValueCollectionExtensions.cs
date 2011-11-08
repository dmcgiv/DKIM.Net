/*
 * DKIM.Net
 * 
 * Copyright (C) 2011 Damien McGivern, damien@mcgiv.com
 * 
 * 
 * 
 * */
using System;
using System.Collections.Specialized;
using JetBrains.Annotations;


namespace DKIM
{
	public static class NameValueCollectionExtensions
	{

		/// <summary>
		/// Adds the name and value item to the start of the collection. 
		/// If the name already exists the origional value is removed.
		/// </summary>
        public static void Prepend([NotNull]this NameValueCollection source, [NotNull]string name, [NotNull]string value)
		{
			if (source == null)
			{
				throw new ArgumentNullException("source");
			}

		    if (name == null)
		    {
		        throw new ArgumentNullException("name");
		    }

		    if (value == null)
		    {
		        throw new ArgumentNullException("value");
		    }

		    if (source.Count > 0)
			{
				var firstKey = source.AllKeys[0];
				if (firstKey != null && firstKey.Equals(name, StringComparison.InvariantCultureIgnoreCase))
				{
					source.Set(name, value);
				}
				else
				{

					// remove so 
					var tmp = new NameValueCollection();
					foreach (var header in source.AllKeys)
					{
						if (!header.Equals(name, StringComparison.InvariantCultureIgnoreCase))
						{
							tmp.Add(header, source[header]);
						}
						source.Remove(header);
					}

					source.Add(name, value);

					foreach (var header in tmp.AllKeys)
					{
						source.Add(header, tmp[header]);
					}
				}

			}
			else
			{
				source.Add(name, value);
			}
		}
	}
}
