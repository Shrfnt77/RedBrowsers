using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RedBrowers.Helper
{
    internal class Utlis
    {
        public static string ToTempFile(string file)
        {
            string tempFile = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            File.Copy(file, tempFile);
            return tempFile;
        }
    }
}
