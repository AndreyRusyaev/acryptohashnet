﻿using NUnit.Framework;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace acryptohashnet.UnitTests
{
    [TestFixture]
    public class Haval224Pass5Tests
    {
        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return HavalTestCases.All().Select(x => new object[] { x.Input, x.Haval224Pass5 });
            }
        }

        [TestCaseSource(nameof(TestCases))]
        public void HashOfString(string input, string expected)
        {
            var actual = new Haval224(HavalPassCount.Pass5).ComputeHash(Encoding.UTF8.GetBytes(input)).ToHexString();
            Assert.That(actual, Is.EqualTo(expected));
        }
    }
}
