
rule n26d5_2d9d6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d9d6a48c0000b12"
     cluster="n26d5.2d9d6a48c0000b12"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['08217870c1c6f3dfbe09682ac3ac5a89dc642d08','92574c3a516686f8f5516e1a1f84221c4312d8c1','f7d7a0689e7252a152e6f76fb8600b2c53a2a371']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d9d6a48c0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
