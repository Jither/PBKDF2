using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using Jither.PBKDF2;
using Mono.Options;

namespace AwpTest
{
    /// <summary>
    /// Quickly hacked together command line tool mainly intended for validating test vectors through e.g. a batch.
    /// This violates all kinds of best practices code-wise.
    /// </summary>
    class Program
    {
        private static string password;
        private static string salt;
        private static long iterations = 1000;
        private static int outputBytes;
        private static string algorithmName = "SHA-512";
        private static string expected;
        private static bool help;

        private static OptionSet options;

        private static byte[] saltBytes;
        private static IPseudoRandomFunction prf;

        private static void Main(string[] args)
        {
            options = new OptionSet
            {
                {"h|help", "Show help", a => help = a != null },
                {"p|password=", "The password to hash", a => password = a},
                {"s|salt=", "Salt to use for hashing", a => salt = a},
                {"i|iterations=", "Number of iterations (default: 1000)", (long a) => iterations = a},
                {"o|outputBytes=", "Number of bytes to output (default: same as algorithm hash size)", (int a) => outputBytes = a},
                {"a|algorithm=", "Algorithm (supported: MD5, SHA-1, SHA-256, SHA-384, SHA-512 - default: SHA-512)", a => algorithmName = a},
                {"e|expected=", "Expected output formatted as a hex string (e.g. 'ab0937af...')", a => expected = a}
            };

            try
            {
                ParseArguments(args);
            }
            catch (Exception e)
            {
                ShowError(e.Message);
            }

            try
            {
                using (var hasher = new PBKDF2DeriveBytes(prf, saltBytes, iterations))
                {
                    var result = hasher.GetBytes(outputBytes);

                    string strResult = BitConverter.ToString(result).Replace("-", "");

                    if (expected != null)
                    {
                        Console.WriteLine(String.Equals(strResult, expected, StringComparison.OrdinalIgnoreCase) ? 1 : 0);
                    }
                    else
                    {
                        Console.WriteLine("{0}: {1}", algorithmName, strResult);
                    }
                }
            }
            finally
            {
                prf.Dispose();
            }
        }

        private static void ParseArguments(IEnumerable<string> args)
        {
            // Somewhat misusing ArgumentException here to throw parameter parser errors...

            try
            {
                options.Parse(args);
            }
            catch (OptionException e)
            {
                throw new ArgumentException(e.Message);
            }

            if (help)
            {
                ShowHelp();
                Environment.Exit(0);
            }

            if (password == null)
            {
                throw new ArgumentException("Missing password parameter");
            }

            if (salt == null)
            {
                throw new ArgumentException("Missing salt parameter");
            }

            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            saltBytes = Encoding.UTF8.GetBytes(salt);

            string normalizedAlgorithmName = algorithmName.Replace("-", "").ToUpperInvariant();

            switch (normalizedAlgorithmName)
            {
                case "MD5":
                    prf = new HMACPseudoRandomFunction<HMACMD5>(passwordBytes);
                    break;
                case "SHA1":
                    prf = new HMACPseudoRandomFunction<HMACSHA1>(passwordBytes);
                    break;
                case "SHA256":
                    prf = new HMACPseudoRandomFunction<HMACSHA256>(passwordBytes);
                    break;
                case "SHA384":
                    prf = new HMACPseudoRandomFunction<HMACSHA384>(passwordBytes);
                    break;
                case "SHA512":
                    prf = new HMACPseudoRandomFunction<HMACSHA512>(passwordBytes);
                    break;
                default:
                    throw new ArgumentException(String.Format("Unsupported algorithm: {0}", algorithmName));
            }

            // Use hash size as default number of output bytes
            outputBytes = outputBytes == 0 ? prf.HashSize : outputBytes;
        }

        private static void ShowHeader()
        {
            Console.WriteLine();
            Console.WriteLine("Anti-weakpasswords command line tool");
            Console.WriteLine("------------------------------------");
        }

        private static void ShowError(string message, params object[] args)
        {
            ShowHeader();
            Console.WriteLine("Error: {0}", String.Format(message, args));
            Console.WriteLine();
            ShowUsage();
            Environment.Exit(1);
        }

        private static void ShowHelp()
        {
            ShowHeader();
            ShowUsage();
        }

        private static void ShowUsage()
        {
            Console.WriteLine("Usage: {0} OPTIONS", Path.GetFileName(Assembly.GetExecutingAssembly().Location));
            Console.WriteLine();
            Console.WriteLine("Options:");
            options.WriteOptionDescriptions(Console.Out);
        }
    }
}
