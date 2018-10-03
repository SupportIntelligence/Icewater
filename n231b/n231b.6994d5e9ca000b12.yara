
rule n231b_6994d5e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231b.6994d5e9ca000b12"
     cluster="n231b.6994d5e9ca000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner script coinhive"
     md5_hashes="['47ec1bca50bab391611993d5f7dff2b6f0fead41','a95b8e0a9348ad5f866f3f7fec90fab8ba8e95fc','d836e040381937ef164af2ae2b8be57936edd766']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231b.6994d5e9ca000b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
