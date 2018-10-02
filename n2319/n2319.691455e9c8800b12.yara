
rule n2319_691455e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.691455e9c8800b12"
     cluster="n2319.691455e9c8800b12"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer miner"
     md5_hashes="['a4efffceaeb1cbb7cfecf770b67b322d3c9fe826','8108c7504928be12be00ebe5a1f40f0a93ca9593','8b20bc7e4cd1bc4cdbca86c1b463ff8cec847a57']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.691455e9c8800b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
