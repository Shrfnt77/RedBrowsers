using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RedBrowers
{
    interface ILoginsReader
    {
        List<Login> ReadLogins();
        string BrowserName { get; }
    }
}
