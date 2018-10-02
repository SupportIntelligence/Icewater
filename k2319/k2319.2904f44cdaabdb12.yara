
rule k2319_2904f44cdaabdb12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.2904f44cdaabdb12"
     cluster="k2319.2904f44cdaabdb12"
     cluster_size="17"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script plugin"
     md5_hashes="['44937f1bbeabf4f5451a6e517df4c8e7b3597463','1540c98106a9971f498f0c89ae524443b787a80d','5f0c56ce0aaf2df7663cd62f1c166c10d0f208cd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.2904f44cdaabdb12"

   strings:
      $hex_string = { 31322e31394532293a2834382c3078323339292929627265616b7d3b7661722053385a3d7b27503167273a2773272c275234273a66756e6374696f6e28772c74 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
