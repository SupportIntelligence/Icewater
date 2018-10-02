
rule n2319_6994d2c9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994d2c9c4000b12"
     cluster="n2319.6994d2c9c4000b12"
     cluster_size="170"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['ed75c4e5caf0cd760420d14af30e0e8509c2b2be','208c449aac30ca9ee0867f8a2dafd81e44a3144f','67143575aff86dfe46a9a52d79bcb7d97ecaad3d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994d2c9c4000b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
