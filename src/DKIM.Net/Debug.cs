/*
 * DKIM.Net
 * 
 * Copyright (C) 2011 Damien McGivern, damien@mcgiv.com
 * 
 * 
 * 
 * */
using System;

namespace DKIM
{
	// todo - remove once stable
	public interface IDebug
	{
		void Write(string text);
		void WriteLine(string text);
		void WriteContent(string name, string text);
		void WriteLine();
	}

	public class ConsoleDebug : IDebug
	{
		public void Write(string text)
		{
			Console.Write(text);
		}

		public void WriteLine(string text)
		{
			Console.WriteLine(text);
		}

		public void WriteContent(string name, string text)
		{
			Console.WriteLine();
			Console.WriteLine("-- " + name + " start ---");
			Console.Write(text);
			Console.WriteLine("-- " + name + " end ---");
			Console.WriteLine();
		}

		public void WriteLine()
		{
			Console.WriteLine();
		}
	}
}
