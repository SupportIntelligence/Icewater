
rule m41a_4918c6c8ea410b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m41a.4918c6c8ea410b12"
     cluster="m41a.4918c6c8ea410b12"
     cluster_size="130"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy adject detrahere"
     md5_hashes="['b39445e46ab51c008e35497482c143e3ddcec7a5','429716fcce8c4bffdaac79a7dedf22b94e53871c','ab10988f47c7c4f7dd4b177bed7a52c3d0191a08']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m41a.4918c6c8ea410b12"

   strings:
      $hex_string = { 74304883c9ff33c0498bf966f2af488d1542180100458bc448f7d18d0409488bcb89442420e8e5b6ffff85c00f88b705000044393516c4010075394c8b0dedaa }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
