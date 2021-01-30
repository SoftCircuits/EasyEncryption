# EasyEncryption

[![NuGet version (SoftCircuits.EasyEncryption)](https://img.shields.io/nuget/v/SoftCircuits.EasyEncryption.svg?style=flat-square)](https://www.nuget.org/packages/SoftCircuits.EasyEncryption/)

```
Install-Package SoftCircuits.EasyEncryption
```

The .NET Framework provides a number of encryption routines. However, these routines generally require a bit of work to set up correctly. Use `EasyEncryption` to make these encryption routines more easily accessible.

## Encrypting a String

The `Encrypt()` method can be used to encrypt a string. Use `DecryptString()` to decrypt the string back to the original.

```cs
Encryption encrypt = new Encryption("Password123", EncryptionAlgorithm.TripleDes);

string original = "This is my message";
string cipher = encrypt.Encrypt(original);
string result = encrypt.DecryptString(cipher);

Debug.Assert(result == message);
```

## Encrypting other Types

The `Encrypt()` method is overloaded to encrypt many different data types. When decrypting, you must use the decryption method specific to the data type you are decrypting. This example encrypts an `int` and `double` value.

```cs
Encryption encrypt = new Encryption("Password123", EncryptionAlgorithm.TripleDes);

int originalInt = 55;
double originalDouble = 123.45;
string cipherInt = encrypt.Encrypt(originalInt);
string cipherDouble = encrypt.Encrypt(originalDouble);
int resultInt = encrypt.DecryptInt32(cipherInt);
double resultDouble = encrypt.DecryptDouble(cipherDouble);

Debug.Assert(resultInt == originalInt);
Debug.Assert(resultDouble == originalDouble);
```

## Streams

`EasyEncryption` also provides the streaming classes `EncryptionWriter` and `EncryptionReader`. These classes work well when encrypting to (or decrypting from) files.

The following example uses the `CreateStreamWriter()` to encrypt a number of integer values to a file.

```cs
Encryption encrypt = new Encryption("Password123", EncryptionAlgorithm.TripleDes);
int[] intValues = { 123, 88, 902, 27, 16, 4, 478, 54 };

using (EncryptionWriter writer = encrypt.CreateStreamWriter(path))
{
    for (int i = 0; i < intValues.Length; i++)
        writer.Write(intValues[i]);
}
```

Use the `CreateStreamReader()` method to decrypt those integer values from the file.

```cs
Encryption encrypt = new Encryption("Password123", EncryptionAlgorithm.TripleDes);
int[] intValues = new int[8];

using (EncryptionReader reader = encrypt.CreateStreamReader(path))
{
    for (int i = 0; i < intValues.Length; i++)
        intValues[i] = reader.ReadInt32();
}
```

Also, the `CreateStreamWriter()` and `CreateStreamReader()` methods are overloaded to accept a stream argument, allowing you to use custom streams. For example, you could use a `MemoryStream` to encrypt data to memory. This is demonstrated in the following example. It also uses the static method `EncodeBytesToString()` method to convert the results to a string. (Note that there is also a corresponding static `DecodeBytesFromString()` method.)

```cs
Encryption encrypt = new Encryption("Password123", EncryptionAlgorithm.TripleDes);

using (MemoryStream stream = new MemoryStream())
using (EncryptionWriter writer = encrypt.CreateStreamWriter(stream))
{
    writer.Write("ABC");
    writer.Write(123);
    writer.Write(123.45);
    string s = Encryption.EncodeBytesToString(stream.ToArray());
}
```

Note that the streaming classes are actually the most efficient way to encrypt and decrypt data. In fact the `Encrypt()` and decryption methods create an instance of `EncryptionWriter` internally (using a `MemoryStream`), even when only encrypting or decrypting a single byte.

In addition, it should be pointed out that the encrypted results produced by these routines include embedded meta data, making the encrypted data slightly larger than it would otherwise be. However, when encrypting to a stream, this data would only be stored once regardless of the number of values added to the stream. The takeaway is that you can use the `Encrypt()` method for a simple encryption, but should use the streaming classes for anything more complex.
