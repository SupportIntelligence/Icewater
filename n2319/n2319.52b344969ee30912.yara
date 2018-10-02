
rule n2319_52b344969ee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.52b344969ee30912"
     cluster="n2319.52b344969ee30912"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['e8b0067971f1d64aa831cef9a51e79c6edd7a74d','69c4e78439fab438ca1e9e9f0bd559f3f678b5bc','e683af31a16caf842bba0f4866f2d2d5e5b0bd67']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.52b344969ee30912"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
