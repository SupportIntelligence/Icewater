
rule k2319_58598cb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.58598cb9c8800b12"
     cluster="k2319.58598cb9c8800b12"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['084b157f99c6de9c296f9134a2d31ba1d280a325','48618a2d009fcd6687796e4524b2b046fc7ba621','f639e49903ddfbd40d7f5f104ac8e94525d93d7b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.58598cb9c8800b12"

   strings:
      $hex_string = { 646f773b666f72287661722048377520696e2077384a3775297b6966284837752e6c656e6774683d3d3d2828307841462c3078323135293c30783143393f353a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
