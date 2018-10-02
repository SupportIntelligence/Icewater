
rule k2319_6918c799c2200932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.6918c799c2200932"
     cluster="k2319.6918c799c2200932"
     cluster_size="46"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['43b1a6d1075b641c9bd703ff9599c759b74670fb','aa0ef875c0f88841850f2c67045f37c78eb6f350','25879cb0c8dfc1bb09f203b40bbef72ee3d99315']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.6918c799c2200932"

   strings:
      $hex_string = { 324531293f2830783231342c3078313044293a283133332e2c3130312e292929627265616b7d3b7661722079314b37743d7b27433077273a2866756e6374696f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
