
rule n26d5_59546a4cc0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.59546a4cc0000b12"
     cluster="n26d5.59546a4cc0000b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik malicious"
     md5_hashes="['49c1dbf6f3c565c5f81a6b203a597353e8c818f8','ec23670e29cfde790084c07238494cdee3f59056','9f8f45b935ab4a2ae8ea109c7a710065f8861c7c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.59546a4cc0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
