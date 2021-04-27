using System;

namespace Stego.Exceptions
{
    class StegoExtractException : Exception
    {
        public StegoExtractException(string message) : base(message) { }
    }
}
