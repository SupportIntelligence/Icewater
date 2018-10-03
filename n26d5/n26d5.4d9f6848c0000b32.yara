
rule n26d5_4d9f6848c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.4d9f6848c0000b32"
     cluster="n26d5.4d9f6848c0000b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik malicious"
     md5_hashes="['1a83da3dd121e3e5d8087ec4a480c41fb2a9436e','ae604f58eaff6432d5307caac4f9a7259ee273d2','0acfd6b0f356c0e6c162762064283e081d6e579e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.4d9f6848c0000b32"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
