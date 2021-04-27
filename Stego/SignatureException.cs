using System;
using System.Collections.Generic;
using System.Text;

namespace Stego
{
    class SignatureException : Exception
    {
        public SignatureException(string message) : base(message) { }
    }
}
