
rule k2319_2904f54cd2abdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2904f54cd2abdb12"
     cluster="k2319.2904f54cd2abdb12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['a8e663db5b1f0f00fa81b072bbca5848c5e1f758','d7fcf6caf234060a2cf80d8eb4eb6ddd2fa361df','af914dbf2399a0f41c817bf92921e8f06e5a829b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2904f54cd2abdb12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
