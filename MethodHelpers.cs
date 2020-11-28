using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;

namespace CA
{
    public static class MethodHelpers
    {
        static readonly string rootFolder = Directory.GetCurrentDirectory();
        static readonly string txtFolder = @$"{Directory.GetParent(rootFolder).Parent.Parent.FullName}\txt\";
        public static readonly Encoding ascii = Encoding.ASCII;

        #region Methods

        /// <summary>
        /// check if a byte represntation of char is a letter uppercase/lowercase
        /// </summary>
        /// <param name="numberASCII"></param>
        /// <returns></returns>
        public static bool checkIfLetter(byte numberASCII)
        {
            if((numberASCII >= 65 && numberASCII <= 90) || (numberASCII >= 97 && numberASCII <= 122 ))
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        /// <summary>
        /// Static utility method to get list of files 
        /// </summary>
        /// <returns>List of files</returns>
        public static List<string> GetFiles()
        {
            List<string> listofFiles = new List<string>();

            foreach(var path in Directory.GetFiles(txtFolder))
            {
                listofFiles.Add(path);
            }
            return listofFiles;
        }

        /// <summary>
        /// Static utility metod for reading files 
        /// </summary>
        /// <param name="listOfFiles"></param>
        /// <param name="type"></param>
        /// <returns>string table</returns>
        public static string[] ReadFile(List<string> listOfFiles)
        {
            string plainText = "";
            string cryptoText = "";
            string encrytpionKey = "";
            string knownText = "";

            try
            {
                plainText = File.ReadAllText(listOfFiles.Find(k => k.Contains("plain.txt")), Encoding.UTF8);
                encrytpionKey = File.ReadAllText(listOfFiles.Find(k => k.Contains("key.txt")), Encoding.UTF8);
                knownText = File.ReadAllText(listOfFiles.Find(k => k.Contains("extra.txt")), Encoding.UTF8);
                cryptoText = File.ReadAllText(listOfFiles.Find(k => k.Contains("crypto.txt")), Encoding.UTF8);
            }
            catch (ArgumentNullException)
            {
                if (!listOfFiles.Exists(k=>k.Contains("plain.txt")))
                {
                    OutputFile(string.Empty, "plain.txt");
                }
                if (!listOfFiles.Exists(k => k.Contains("crypto.txt")))
                {
                    OutputFile(string.Empty, "crypto.txt");
                }
                if (!listOfFiles.Exists(k => k.Contains("key.txt")))
                {
                    OutputFile(string.Empty, "key.txt");
                }
                if (!listOfFiles.Exists(k => k.Contains("extra.txt")))
                {
                    OutputFile(string.Empty, "extra.txt");
                }
            }
            catch (FileNotFoundException)
            {
                if (!listOfFiles.Exists(k => k.Contains("plain.txt")))
                {
                    OutputFile(string.Empty, "plain.txt");
                }
                if (!listOfFiles.Exists(k => k.Contains("crypto.txt")))
                {
                    OutputFile(string.Empty, "crypto.txt");
                }
                if (!listOfFiles.Exists(k => k.Contains("key.txt")))
                {
                    OutputFile(string.Empty, "key.txt");
                }
                if (!listOfFiles.Exists(k => k.Contains("extra.txt")))
                {
                    OutputFile(string.Empty, "extra.txt");
                }
            }
           
                    
            return new string[] { plainText, cryptoText, encrytpionKey,knownText};
        }

        /// <summary>
        /// Read crypto.txt
        /// </summary>
        /// <param name="listOfFiles"></param>
        /// <returns>string</returns>
        public static string ReadCryptoFile(List<string> listOfFiles)
        {
            return File.ReadAllText(listOfFiles.Find(k => k.Contains("crypto.txt")), Encoding.UTF8);
        }

        /// <summary>
        /// Write to txt 
        /// </summary>
        /// <param name="outputText"></param>
        /// <param name="fileToWrite"></param>
        public static void OutputFile(string outputText, string fileToWrite)
        {
            string folder = txtFolder + fileToWrite;

            File.WriteAllText(folder, outputText);
        }

        /// <summary>
        /// write to txt array
        /// </summary>
        /// <param name="outputText"></param>
        /// <param name="fileToWrite"></param>
        public static void OutputFileArray(string[] outputText, string fileToWrite)
        {
            string folder = txtFolder + fileToWrite;
            try
            {
                File.WriteAllLines(folder, outputText, Encoding.UTF8);

            }
            catch(Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }

        #endregion

        #region Data Members 

        public readonly static char[] alphUpper = {
                            'A','B','C','D',
                            'E','F','G','H',
                            'I',
                            'J','K','L','M',
                            'N','O','P','Q',
                            'R','S','T','U',
                            'V','W','X','Y',
                            'Z'
                        };
        public readonly static char[] alphLower = {
                            'a','b','c','d',
                            'e','f','g','h',
                            'i',
                            'j','k','l','m',
                            'n','o','p','q',
                            'r','s','t','u',
                            'v','w','x','y',
                            'z'
                        };
        #endregion
    }
}
