
rule k2319_3686ec49cd527b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.3686ec49cd527b12"
     cluster="k2319.3686ec49cd527b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script fffazo"
     md5_hashes="['8ab1d279e82e3e7ff657ee59d311867367542237','06152019c486980bdd27868350bfd5fecc7202f2','2d6ebd606ea4835b823e297b57b6ac218af20da2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.3686ec49cd527b12"

   strings:
      $hex_string = { 3f28352e383245322c313139293a2833352c3132352e292929627265616b7d3b7661722051305137593d7b27703547273a2230222c27763347273a2266696775 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
