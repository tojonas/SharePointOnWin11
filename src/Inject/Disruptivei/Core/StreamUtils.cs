namespace Disruptivei.Core
{
    using System;
    using System.IO;

    public static class StreamUtils
    {
        public static Stream Base64DecodeToStream(string s)
        {
            return new MemoryStream(Convert.FromBase64String(s));
        }
        public static string Base64EncodeStream(Stream stm)
        {
            if (stm.CanSeek)
            {
                stm.Seek(0, SeekOrigin.Begin);
            }
            using (var ms = new MemoryStream())
            {
                stm.CopyTo(ms);
                return Convert.ToBase64String(ms.ToArray());
            }
        }
        public static void SaveToFile(Stream input, string filePath)
        {
            using (var output = File.Create(filePath))
            {
                if (input.CanSeek)
                {
                    input.Seek(0L, SeekOrigin.Begin);
                }
                input.CopyTo(output);
            }
        }
    }

}

