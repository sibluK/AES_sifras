using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace AES_sifras
{
    public class Program
    {
        private static string inputFile = "C:\\Users\\pugli\\OneDrive\\Stalinis kompiuteris\\Desktop\\Kolegija\\4 semestras\\INFORMACIJOS SAUGUMAS\\AES_sifras\\input.txt";

        public static string ReadFromFile(string fileName)
        {
            string text;

            using (StreamReader reader = new StreamReader(fileName))
            {
                text = reader.ReadToEnd();
            }
            return text;
        }

        public static void WriteToFile(string fileName, string text)
        {
            using (StreamWriter writer = new StreamWriter(fileName))
            {
                writer.Write(text);
            }
        }

        public static byte[] sifruoti(string tekstas, byte[] raktas, CipherMode mode)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = raktas;
                aes.Mode = mode;

                if (mode == CipherMode.OFB)
                    aes.Padding = PaddingMode.None;
                else
                    aes.Padding = PaddingMode.PKCS7;

                aes.GenerateIV();

                /*
                Console.WriteLine();
                Console.WriteLine($"IV: {BitConverter.ToString(aes.IV).Replace("-", "")}");
                Console.WriteLine();
                */

                byte[] iv = aes.IV;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);


                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(tekstas);
                        }
                        return iv.Concat(msEncrypt.ToArray()).ToArray();
                    }
                }
            }
        }

        public static string desifruoti(byte[] tekstas, byte[] raktas, CipherMode mode)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = raktas;
                aes.Mode = mode;

                if (mode == CipherMode.OFB)
                    aes.Padding = PaddingMode.None;
                else
                    aes.Padding = PaddingMode.PKCS7;

                byte[] iv = tekstas.Take(aes.BlockSize / 8).ToArray();
                byte[] ciphertext = tekstas.Skip(aes.BlockSize / 8).ToArray();
                aes.IV = iv;

                /*
                Console.WriteLine();
                Console.WriteLine($"IV: {BitConverter.ToString(aes.IV).Replace("-", "")}");
                Console.WriteLine();
                */

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var msDecrypt = new MemoryStream(ciphertext))
                {
                    using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (var srDecrypt = new StreamReader(csDecrypt))
                        {
                            return srDecrypt.ReadToEnd();
                        }
                    }
                }
            }
        }

        public static byte[] generateValidKey(string raktas, int raktoDydis)
        {
            using (var sha256 = SHA256.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(raktas);
                byte[] hashedBytes = sha256.ComputeHash(inputBytes);

                Array.Resize(ref hashedBytes, raktoDydis);

                return hashedBytes;
            }
        }

        public static byte[] inputKey()
        {
            Console.Write("Ivesktite raktą: ");
            string raktas = Console.ReadLine();
            Console.WriteLine();
            Console.WriteLine("Iš kiek bitų sudaryti raktą:");
            Console.WriteLine("1. 128bit");
            Console.WriteLine("2. 192bit");
            Console.WriteLine("3. 256bit");
            Console.WriteLine();
            Console.Write("Pasirinkimas: ");
            string pasirinkimas = Console.ReadLine();

            while (pasirinkimas != "1" && pasirinkimas != "2" && pasirinkimas != "3")
            {
                Console.Write("Tokio pasirinkimo nėra! Įveskite tinkamą: ");
                pasirinkimas = Console.ReadLine();
            }

            if (pasirinkimas == "1")
            {
                return generateValidKey(raktas, 16);
            }
            else if (pasirinkimas == "2")
            {
                return generateValidKey(raktas, 24);
            }
            else if (pasirinkimas == "3")
            {
                return generateValidKey(raktas, 32);
            }
            return null;
        }

        public static CipherMode getMode()
        {
            Console.WriteLine();
            Console.WriteLine("Pasirinkite modą:");
            Console.WriteLine("1. Electronic Codebook Mode (ECB);");
            Console.WriteLine("2. Cipher Block Chaining Mode (CBC);");
            Console.WriteLine("3. Output Feedback Mode (OFB); // NEVEIKIA SU AES");
            Console.WriteLine("4. Cipher Feedback Mode (CFB);");
            Console.WriteLine("5. Counter Mode (CTR); // NEVEIKIA, NERA BIBLIOTEKOS");
            Console.WriteLine();
            Console.Write("Pasirinkimas: ");
            string pasirinkimas = Console.ReadLine();

            while (pasirinkimas != "1" && pasirinkimas != "2" && pasirinkimas != "3" && pasirinkimas != "4" && pasirinkimas != "5")
            {
                Console.Write("Netinkamas pasirinkimas. Pasirinkite kitą: ");
                pasirinkimas = Console.ReadLine();
            }

            switch (pasirinkimas)
            {
                case "1":
                    return CipherMode.ECB;
                case "2":
                    return CipherMode.CBC;
                case "3":
                    return CipherMode.OFB; // NEVEIKIA SU AES
                case "4":
                    return CipherMode.CFB;
                case "5":
                    return CipherMode.ECB; // NEVEIKIA, NERA BIBLIOTEKOS
                default:
                    return CipherMode.ECB;
            }
        }


        public static void Main(string[] args)
        {
            bool run = true;
            while (run)
            {
                Console.WriteLine("----------------------------------------------------------");
                Console.WriteLine("Pasirinkite:");
                Console.WriteLine("1. Sifravimas (AES metodas);");
                Console.WriteLine("2. Desifavimas (AES metodas);");
                Console.WriteLine("3. Baigti.");
                Console.WriteLine();
                Console.Write("Pasirinkimas: ");
                string pasirinkimas = Console.ReadLine();

                byte[] tinkamasRaktas;
                byte[] sifruotiBaitai;
                string tekstas;
                char rasymoPasirinkimas;

                switch (pasirinkimas)
                {
                    case "1": // Sifravimas AES metodu
                        Console.WriteLine();
                        Console.Write("Ivesktite tekstą, kurį norite užšifruoti: ");
                        tekstas = Console.ReadLine();
                        
                        Console.WriteLine();

                        tinkamasRaktas = inputKey();

                        sifruotiBaitai = sifruoti(tekstas, tinkamasRaktas, getMode());

                        Console.WriteLine();
                        Console.Write("Ar norite įrašyti šifruotą tekstą į failą? (T/N): ");
                        rasymoPasirinkimas = char.Parse(Console.ReadLine());

                        while (rasymoPasirinkimas != 'T' && rasymoPasirinkimas != 'N')
                        {
                            Console.Write("Tokio pasirinkimo nėra! Įveskite tinkamą: ");
                            rasymoPasirinkimas = char.Parse(Console.ReadLine());
                        }

                        if (rasymoPasirinkimas == 'T')
                        {
                            WriteToFile(inputFile, Convert.ToBase64String(sifruotiBaitai));
                            Console.WriteLine();
                            Console.WriteLine("Šifruotas tekstas sėkmingai įrašytas į failą!");
                            Console.WriteLine();
                        }
                        else
                            Console.WriteLine();
                            Console.WriteLine("----------------------------------------------------------");
                            Console.WriteLine($"Ivestas tekstas: {tekstas}");
                            Console.WriteLine($"Šifruotas tekstas: {Convert.ToBase64String(sifruotiBaitai)}");
                        break;

                    case "2": // Desifravimas AES metodu
                        bool runCase2 = true;
                        while (runCase2)
                        {
                            Console.WriteLine();
                            Console.WriteLine("Pasirinkite:");
                            Console.WriteLine("1. Įrašyti sifruotą tekstą komandinėje eilutėje.");
                            Console.WriteLine("2. Nuskaityti šifruotą tekstą iš failo.");
                            Console.WriteLine("3. Grįžti atgal");
                            Console.WriteLine();
                            Console.Write("Pasirinkimas: ");
                            string pasirinkimasCase2 = Console.ReadLine();

                            while(pasirinkimasCase2 != "1" && pasirinkimasCase2 != "2" && pasirinkimasCase2 != "3")
                            {
                                Console.Write("Tokio pasirinkimo nėra! Įveskite tinkamą: ");
                                pasirinkimasCase2 = Console.ReadLine();
                            }

                            switch (pasirinkimasCase2)
                            {
                                case "1":
                                    Console.WriteLine();
                                    Console.Write("Ivesktite tekstą, kurį norite dešifruoti: ");
                                    sifruotiBaitai = Convert.FromBase64String(Console.ReadLine());

                                    tinkamasRaktas = inputKey();

                                    CipherMode mode1 = getMode();

                                    Console.Write($"Desifruotas tekstas: {desifruoti(sifruotiBaitai, tinkamasRaktas, mode1)}");
                                    Console.WriteLine();

                                    runCase2 = false;
                                    break;

                                case "2":
                                    Console.WriteLine();

                                    tekstas = ReadFromFile(inputFile);
                                    tinkamasRaktas = inputKey();
                                    CipherMode mode2 = getMode();

                                    Console.WriteLine();
                                    Console.WriteLine("----------------------------------------------------------");
                                    Console.WriteLine($"Sifruotas tekstas: {tekstas}");
                                    Console.WriteLine($"Desifruotas tekstas: {desifruoti(Convert.FromBase64String(tekstas), tinkamasRaktas, mode2)}");

                                    runCase2 = false;
                                    break;

                                case "3":
                                    runCase2 = false;
                                    break;
                            }
                        }
                        break;

                    case "3":
                        run = false;
                        break;

                    default:
                        Console.WriteLine();
                        Console.WriteLine("Tokio pasirinkimo nėra!");
                        break;
                }
            }
        }
    }
}
