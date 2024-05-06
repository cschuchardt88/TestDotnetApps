using Neo.Cryptography;
using System.Security.Cryptography;
using System.Text;

ECDsa ecdsa = ECDsaOpenSsl.Create(ECCurve.CreateFromFriendlyName("secP256k1"));
ECParameters s = ecdsa.ExportParameters(true);
byte[] bytes = Encoding.UTF8.GetBytes("Hello");
var signature = ecdsa.SignData(bytes, HashAlgorithmName.SHA256);
var result = Crypto.VerifySignature(bytes, signature, [0x04, .. s.Q.X, .. s.Q.Y], Neo.Cryptography.ECC.ECCurve.Secp256k1);

Console.WriteLine(Convert.ToHexString(signature));

var shake256 = new Shake256();

Console.WriteLine(Convert.ToHexString(Shake256.HashData(Encoding.UTF8.GetBytes("Hello"), 256)));