
rule k2319_6918c399c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6918c399c2200932"
     cluster="k2319.6918c399c2200932"
     cluster_size="9"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['97539637214412fd641838e168fb03bc29ffab68','4474da6365e3f91142713317186bf1f9146c6584','342aa5049a9d38d0350be55a1acfa6e485cfbe9d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6918c399c2200932"

   strings:
      $hex_string = { 324531293f2830783231342c3078313044293a283133332e2c3130312e292929627265616b7d3b7661722079314b37743d7b27433077273a2866756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
