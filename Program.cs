using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CA
{
    class Program
    {
        /// <summary>
        /// EXAMPLE:
        /// CEJ - Szyfr cezara/szyfrowanie/kryptoanaliza z tekstem jawnym
        /// CEK - Szyfr cezara/szyfrowanie/kryptoanaliza kryptogram
        /// CDJ - Szyfr cezara/deszyfrowanie/kryptoanaliza z tekstem jawnym
        /// CDK - Szyfr cezara/deszyfrowaniekryptoanaliza kryptogram
        /// AEJ - Szyfr Aaficzny/szyfrowanie/kryptoanaliza z tekstem jawnym
        /// AEK - Szyfr Aaficzny/szyfrowanie/kryptoanaliza kryptogram
        /// ADJ - Szyfr Aaficzny/deszyfrowanie/kryptoanaliza z tekstem jawnym
        /// ADK - Szyfr Aaficzny/deszyfrowanie/kryptoanaliza kryptogram
        /// </summary>
        static void Main(string[] args)
        {
            
            
            while (true)
            {
                List<string> files = MethodHelpers.GetFiles();
                string doSth = Console.ReadLine();
                string ocmpleted = doSth.Replace("-", string.Empty)
                                    .Replace(" ", string.Empty);
                string[] cases = MethodHelpers.ReadFile(files);
                CesarEncrytpion ce = new CesarEncrytpion(cases[0], cases[1], cases[2]);
                AffineEncryption aej = new AffineEncryption(cases[0], cases[1], cases[2]);

                switch (ocmpleted)
                {

                    case "ce":
                        ce.EncryptionStart();
                        break;
                    case "cj":
                        ce.KnownPlainTextAttack(cases[3]);
                        break;
                    case "cd":
                        ce.DecryptionStart();
                        break;
                    case "ck":
                        ce.UnknownPlanTextAttack();
                        break;
                    case "cej":
                        ce.EncryptionStart();
                        ce.KnownPlainTextAttack(cases[3]);
                        break;
                    case "cek":
                        ce.EncryptionStart();
                        ce.UnknownPlanTextAttack();
                        break;
                    case "cdj":
                        ce.DecryptionStart();
                        ce.KnownPlainTextAttack(cases[3]);
                        break;
                    case "cdk":
                        ce.DecryptionStart();
                        ce.UnknownPlanTextAttack();
                        break;
                        
                    case "ae":
                        aej.EncryptionStart();
                        break;
                    case "aj":
                        //aej.encryptedText = MethodHelpers.ReadCryptoFile(files);
                        aej.KnownPlainTextAttack(cases[3]);
                        break;
                    case "ad":
                        aej.DecryptionStart();
                        break;
                    case "ak":
                        aej.UnknownPlanTextAttack();
                        break;

                    case "aej":
                        aej.EncryptionStart();
                        aej.KnownPlainTextAttack(cases[3]);
                        break;
                    case "aek":
                        aej.EncryptionStart();
                        aej.UnknownPlanTextAttack();
                        break;
                    case "adj":
                        aej.DecryptionStart();
                        aej.KnownPlainTextAttack(cases[3]);
                        break;
                    case "adk":
                        aej.DecryptionStart();
                        aej.UnknownPlanTextAttack();
                        break;

                    default:
                        Console.WriteLine("Wrong input");
                        break;
                }
            }
          
        }

        
    }
    
    

}
