
rule k2319_101896a9c9000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.101896a9c9000912"
     cluster="k2319.101896a9c9000912"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['811134bd74a640d5fc2bb19a722cca8e06fcb887','9cea32b640f8577a0d73211ed38889b7a099a857','fa646f39b25c75814c8cd3c83aa544ad50d57229']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.101896a9c9000912"

   strings:
      $hex_string = { 3131362c3078314546292929627265616b7d3b766172204c374c3d7b27473377273a22436f222c27753077273a2250222c274b37273a66756e6374696f6e2848 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
