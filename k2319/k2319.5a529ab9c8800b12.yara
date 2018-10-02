
rule k2319_5a529ab9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a529ab9c8800b12"
     cluster="k2319.5a529ab9c8800b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['d0be681cc5858217b17ab92316f6f5922fe3d413','fcd421614e739025410a054b85a679ac2655b23c','52c8bdc702d2d125dd1f428953941d8e9470e881']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a529ab9c8800b12"

   strings:
      $hex_string = { 3a2830783136462c32372e39304531292929627265616b7d3b76617220713941343d7b27573945273a226f64222c27533144273a66756e6374696f6e28542c76 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
