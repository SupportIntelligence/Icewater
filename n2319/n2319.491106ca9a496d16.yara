
rule n2319_491106ca9a496d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.491106ca9a496d16"
     cluster="n2319.491106ca9a496d16"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script coinminer coinhive"
     md5_hashes="['98e82a50d6d64abbf93cedabcb7439a93a107597','a5cc10d2a0c1f52efdc29b994eb862826aafe28e','07901a3981dd959f277d95cff5bbc10eb742a1d7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.491106ca9a496d16"

   strings:
      $hex_string = { 2f55492d5472616e736974696f6e3e227d2c7265674578703a7b6573636170653a2f5b2d5b5c5d7b7d28292a2b3f2e2c5c5c5e247c235c735d2f672c71756f74 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
