
rule k2319_2904b4d5d9abdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2904b4d5d9abdb12"
     cluster="k2319.2904b4d5d9abdb12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['4940689ff5a7f103d6a31cc8ff8b99169209f6da','0a9b1df4dc0af775b82360dffefaf6de566fcecd','e9fcb18231b2eee6287833bdcec2c7413bdfc0d8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2904b4d5d9abdb12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
