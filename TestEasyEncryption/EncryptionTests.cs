using EasyEncryption;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;

namespace TestEasyEncryption
{
    [TestClass]
    public class EncryptionTests
    {
        [TestMethod]
        public void TestEncryption()
        {
            foreach (EncryptionAlgorithm algorithm in Enum.GetValues(typeof(EncryptionAlgorithm)))
            {
                Encryption encrypt = new Encryption("Password123", algorithm);

                foreach (var i in new List<String> { /*null,*/ String.Empty, "a", "ab", "abcdefghijklmnopqrstuvwxyz" })
                    Assert.AreEqual(i, encrypt.DecryptString(encrypt.Encrypt(i)));
                foreach (var i in new List<Char> { Char.MinValue, (char)(Char.MinValue + 1), 'a', 'b', '\x1234', (char)(Char.MaxValue - 1), Char.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptChar(encrypt.Encrypt(i)));
                foreach (var i in new List<Boolean> { true, false })
                    Assert.AreEqual(i, encrypt.DecryptBoolean(encrypt.Encrypt(i)));
                foreach (var i in new List<Byte> { Byte.MinValue, Byte.MinValue + 1, 0, 1, 123, Byte.MaxValue - 1, Byte.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptByte(encrypt.Encrypt(i)));
                foreach (var i in new List<SByte> { SByte.MinValue, SByte.MinValue + 1, -123, -1, 0, 1, 123, SByte.MaxValue - 1, SByte.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptSByte(encrypt.Encrypt(i)));
                foreach (var i in new List<Int16> { Int16.MinValue, Int16.MinValue + 1, -12345, -1, 0, 1, 12345, Int16.MaxValue - 1, Int16.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptInt16(encrypt.Encrypt(i)));
                foreach (var i in new List<UInt16> { UInt16.MinValue, UInt16.MinValue + 1, 0, 1, 12345, UInt16.MaxValue - 1, UInt16.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptUInt16(encrypt.Encrypt(i)));
                foreach (var i in new List<Int32> { Int32.MinValue, Int32.MinValue + 1, -12345, -1, 0, 1, 12345, Int32.MaxValue - 1, Int32.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptInt32(encrypt.Encrypt(i)));
                foreach (var i in new List<UInt32> { UInt32.MinValue, UInt32.MinValue + 1, 0, 1, 12345, UInt32.MaxValue - 1, UInt32.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptUInt32(encrypt.Encrypt(i)));
                foreach (var i in new List<Int64> { Int64.MinValue, Int64.MinValue + 1, -12345, -1, 0, 1, 12345, Int64.MaxValue - 1, Int64.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptInt64(encrypt.Encrypt(i)));
                foreach (var i in new List<UInt64> { UInt64.MinValue, UInt64.MinValue + 1, 0, 1, 12345, UInt64.MaxValue - 1, UInt64.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptUInt64(encrypt.Encrypt(i)));
                foreach (var i in new List<Single> { Single.MinValue, Single.MinValue + .5f, -12345.5f, -1.5f, -.001f, 0, .001f, 1.5f, 12345.5f, Single.MaxValue - .5f, Single.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptSingle(encrypt.Encrypt(i)));
                foreach (var i in new List<Double> { Double.MinValue, Double.MinValue + .5, -12345.5, 1.5, .001, 0, .001, 1.5, 12345.5, Double.MaxValue - 1, Double.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptDouble(encrypt.Encrypt(i)));
                foreach (var i in new List<Decimal> { Decimal.MinValue, Decimal.MinValue + .5m, -12345.5m, 1.5m, .001m, 0, .001m, 1.5m, 12345.5m, Decimal.MaxValue - 1, Decimal.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptDecimal(encrypt.Encrypt(i)));
                foreach (var i in new List<DateTime> { DateTime.MinValue, DateTime.MinValue.AddMilliseconds(1), DateTime.Now, DateTime.Today, DateTime.MaxValue.AddMilliseconds(-1), DateTime.MaxValue })
                    Assert.AreEqual(i, encrypt.DecryptDateTime(encrypt.Encrypt(i)));
                byte[] barray = new byte[] { 0, 1, 128, 0xfe, 0xff };
                CollectionAssert.AreEqual(barray, encrypt.DecryptByteArray(encrypt.Encrypt(barray)));
                string[] sarray = new string[] { /*null,*/ String.Empty, "a", "ab", "abcdefghijklmnopqrstuvwxyz" };
                CollectionAssert.AreEqual(sarray, encrypt.DecryptStringArray(encrypt.Encrypt(sarray)));
            }
        }

        [TestMethod]
        public void TestFileEncryption()
        {
            string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "EncryptionTests");
            Random random = new Random();

            foreach (EncryptionAlgorithm algorithm in Enum.GetValues(typeof(EncryptionAlgorithm)))
            {
                Encryption encrypt = new Encryption("Password123", algorithm);
                int[] intValues = new int[16];

                for (int i = 0; i < intValues.Length; i++)
                    intValues[i] = random.Next(int.MinValue, int.MaxValue);

                using (EncryptionWriter writer = encrypt.CreateStreamWriter(path))
                {
                    for (int i = 0; i < intValues.Length; i++)
                        writer.Write(intValues[i]);
                }

                using (EncryptionReader reader = encrypt.CreateStreamReader(path))
                {
                    for (int i = 0; i < intValues.Length; i++)
                        Assert.AreEqual(intValues[i], reader.ReadInt32());
                }

                File.Delete(path);
            }
        }
    }
}
