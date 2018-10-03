
rule n26d5_0d1f6848c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.0d1f6848c0000b32"
     cluster="n26d5.0d1f6848c0000b32"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['251e53b62377a2d7e93b9c67e4bab8f72b0ce998','969c797c32cb8596ad62c45c4dd3bb6187ea6328','70af6ff07055ddc5111dc30d691c0334950157f7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.0d1f6848c0000b32"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
