
rule n2319_6994d899c6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994d899c6220b12"
     cluster="n2319.6994d899c6220b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['bfab7474c0b8c58531d538eb2626c0fa7d431487','c1ffe862dfe5298ae54fdaa8d7a1a4ed8c3b6d50','ef4fae542f78c70eed411d97d6b7ece947914a44']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994d899c6220b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
