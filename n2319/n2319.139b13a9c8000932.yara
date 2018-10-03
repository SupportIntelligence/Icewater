
rule n2319_139b13a9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.139b13a9c8000932"
     cluster="n2319.139b13a9c8000932"
     cluster_size="73"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['abf7f2e4852e3d68bbeaf7505984fa44d5ad633b','5aea7e615585f03ff575e52448e3be69d4371b59','1fcb6464612fd7710e7dc87b54f13e2e0b720fee']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.139b13a9c8000932"

   strings:
      $hex_string = { 74262621772e6973456d7074794f626a6563742874297d7d3b766172204a3d6e657720512c4b3d6e657720512c5a3d2f5e283f3a5c7b5b5c775c575d2a5c7d7c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
