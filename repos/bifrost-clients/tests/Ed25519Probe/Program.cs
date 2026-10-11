using System.Security.Cryptography;
using System.Text;
using Bifrost.Release;

var vector = new
{
    Seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    Public = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    Signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
};
static byte[] Hex(string value) => Convert.FromHexString(value);
var signature = Ed25519.Sign(Array.Empty<byte>(), Hex(vector.Seed), out var publicKey);
if (!publicKey.SequenceEqual(Hex(vector.Public)) || !signature.SequenceEqual(Hex(vector.Signature)) || !Ed25519.Verify(signature, Array.Empty<byte>(), publicKey))
    throw new CryptographicException("Ed25519 RFC8032 vector failed");
var message = Encoding.UTF8.GetBytes("bifrost-native-control-plane");
var signed = Ed25519.Sign(message, Hex(vector.Seed), out var samePublic);
if (!samePublic.SequenceEqual(publicKey) || !Ed25519.Verify(signed, message, publicKey) || Ed25519.Verify(signed, Encoding.UTF8.GetBytes("tampered"), publicKey))
    throw new CryptographicException("Ed25519 tamper vector failed");
Console.WriteLine("Ed25519 RFC8032/native vector PASS");
