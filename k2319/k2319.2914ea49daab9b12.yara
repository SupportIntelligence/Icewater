
rule k2319_2914ea49daab9b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2914ea49daab9b12"
     cluster="k2319.2914ea49daab9b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['2688d05df7902332efd3332d1d3a6d2de2270ee9','c228f88c34ded1554306520211a7f3ba45843d50','81e07660a5d2d2d6c755f0ca169c5316dd235810']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2914ea49daab9b12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
