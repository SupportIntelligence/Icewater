
rule m26d7_28625ec3cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.28625ec3cc000b12"
     cluster="m26d7.28625ec3cc000b12"
     cluster_size="115"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious engine heuristic"
     md5_hashes="['247ff2113f8bdbfc9144e41fefeed3f840f02b85','10ffbd86c6e3505d09f92f75e9deecfef340d1bd','f289d425809265d12d8bedb124f1e9e88cab6bc1']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.28625ec3cc000b12"

   strings:
      $hex_string = { 74043c20750739f3c6060072e28d65f45b5e5f5dc204005589e557565383ec5c8b7d0c85ff790aa1cc834200f7d78b3cb88b4508bbd0834200033d647b42002d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
