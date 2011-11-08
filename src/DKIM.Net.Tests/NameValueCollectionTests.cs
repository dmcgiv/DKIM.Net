using System;
using System.Collections.Specialized;
using NUnit.Framework;

namespace DKIM.Tests
{

	/// <summary>
	/// Tests the NameValueCollection Prepend extension method
	/// </summary>
	[TestFixture]
	public class NameValueCollectionTests
	{


		[Test]
		[ExpectedException(typeof(ArgumentNullException))]
		public void Null()
		{
			var orig = new NameValueCollection();
			orig = null;

			orig.Prepend("name", "value");


		}

		[Test]
		public void Empty()
		{
			var orig = new NameValueCollection();

			orig.Prepend("name", "value");


			Assert.AreEqual(1, orig.Count);
			Assert.AreEqual("value", orig[0]);

		}



		[Test]
		public void SimgleItemNameDoesNotExist()
		{
			var orig = new NameValueCollection
			           	{
			           		{"n", "v"}
			           	};

			orig.Prepend("name", "value");


			Assert.AreEqual(2, orig.Count);
			Assert.AreEqual("value", orig[0]);
			Assert.AreEqual("v", orig[1]);

		}

		[Test]
		public void SimgleItemNameDoesExist()
		{
			var orig = new NameValueCollection
			           	{
			           		{"name", "v"}
			           	};

			orig.Prepend("name", "value");


			Assert.AreEqual(1, orig.Count);
			Assert.AreEqual("value", orig[0]);
			

		}


		[Test]
		public void MiltipleItemNameDoesExistAndAtStart()
		{
			var orig = new NameValueCollection
			           	{
			           		{"name", "v"}, 
							{"name2", "v2"}
			           	};

			orig.Prepend("name", "value");


			Assert.AreEqual(2, orig.Count);
			Assert.AreEqual("value", orig[0]);
			Assert.AreEqual("v2", orig[1]);


		}


		[Test]
		public void MiltipleItemNameDoesExistAndNotAtStart()
		{
			var orig = new NameValueCollection
			           	{
			           		{"name2", "v2"}, 
							{"name", "v"}
			           	};

			orig.Prepend("name", "value");


			Assert.AreEqual(2, orig.Count);
			Assert.AreEqual("value", orig[0]);
			Assert.AreEqual("v2", orig[1]);


		}

	}
}
