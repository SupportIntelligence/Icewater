
rule k2319_2904b4d4d9abdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2904b4d4d9abdb12"
     cluster="k2319.2904b4d4d9abdb12"
     cluster_size="26"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script browser"
     md5_hashes="['abf05e585d5b5cbf41f5f188b38bea2fef86faf2','0d8dcde14384b66fee72b94bfab0a6f1d261fe8c','dfe96cc1c975db26a2b653bc868d17f4fc4e1fce']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2904b4d4d9abdb12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
