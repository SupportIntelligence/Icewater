
rule k2319_391946b9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.391946b9c8800932"
     cluster="k2319.391946b9c8800932"
     cluster_size="18"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['4e7ded0803c1797b37e905af96adf83e78437492','7fad8c308e431c28f5a5e97e7ce72ff5a41043a1','fda9425f80e5ee900d79aabdd004064c2bd0a8dd']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.391946b9c8800932"

   strings:
      $hex_string = { 323f283131312c313139293a28307842422c34292929627265616b7d3b7661722047344a35633d7b27453665273a2243222c27673663273a66756e6374696f6e }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
