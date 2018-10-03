
rule n26d5_2d1ce848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d1ce848c0000b12"
     cluster="n26d5.2d1ce848c0000b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['1f93ab0771c531fb30d7b745e60c9a94c25b8f36','d33efdb5ac9e58eb91eef15d2a86ae311c1e4837','25425574b83df1198878e55386946a2bf42ef6f3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d1ce848c0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
