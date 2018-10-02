
rule m2319_3ab2788b251c4a11
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3ab2788b251c4a11"
     cluster="m2319.3ab2788b251c4a11"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="coinhive script html"
     md5_hashes="['aabd3f801c681e6cfc6c082cb11ca972037c9eb3','1b232ec89338a939b6f2de043322cb1cd18e36dd','62718015a00de1bf6d3c46338f8afa162a215453']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m2319.3ab2788b251c4a11"

   strings:
      $hex_string = { 33355b31395d5d2b205f3078646133355b32335d7d7d7d2c73656e643a66756e6374696f6e28297b7472797b766172205f30786236396678613d646f63756d65 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
