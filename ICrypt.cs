using System;
using System.Collections.Generic;
using System.Text;

namespace CA
{
    public interface Encryption
    {
        public void EncryptionStart();
        public void DecryptionStart();
        public void KnownPlainTextAttack(string knownText);
        public void UnknownPlanTextAttack();
        public bool KeyValidation();

        public string plainText { get; set; }
        public string encryptedText { get; set; }
        public string encrytpionKey { get; set; }

    }
}
