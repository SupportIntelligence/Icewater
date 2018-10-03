
rule o2319_611cea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2319.611cea48c0000b12"
     cluster="o2319.611cea48c0000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['1158c531138017ca617fa74c8670e8d066a51b61','7b520864a19f40540ab74fc8d19bf48a4c6bb543','82f1f5dd501c7b0ef37902067fc2f6a010217fd0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o2319.611cea48c0000b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
