
rule k2319_5a529eb9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.5a529eb9c8800b12"
     cluster="k2319.5a529eb9c8800b12"
     cluster_size="15"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik diplugem expkit"
     md5_hashes="['a0843f9fcdee95b4e71c770380b485a324653c38','def23c38c886d85b2ab4c152ba6d0bb6304db11f','53a834509082e2f6af2ee348bbb5a7ecdfba3419']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.5a529eb9c8800b12"

   strings:
      $hex_string = { 3a2830783136462c32372e39304531292929627265616b7d3b76617220713941343d7b27573945273a226f64222c27533144273a66756e6374696f6e28542c76 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
