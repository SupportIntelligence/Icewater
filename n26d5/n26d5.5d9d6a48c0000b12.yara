
rule n26d5_5d9d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.5d9d6a48c0000b12"
     cluster="n26d5.5d9d6a48c0000b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik malicious"
     md5_hashes="['735c2e75a883559a2e3123e356bbd8add87e61d8','2b43caf79b766a5a09110ef2deea8c434181e3a4','aedfd533de5bb58dee43210a05f23b83e57d995e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.5d9d6a48c0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
