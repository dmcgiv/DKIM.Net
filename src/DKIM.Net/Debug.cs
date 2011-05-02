using System;

namespace McGiv.DKIM
{
	public interface IDebug
	{
		void Write(string text);
		void WriteLine(string text);
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

		public void WriteLine()
		{
			Console.WriteLine();
		}
	}
}
