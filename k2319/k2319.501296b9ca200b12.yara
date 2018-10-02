
rule k2319_501296b9ca200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.501296b9ca200b12"
     cluster="k2319.501296b9ca200b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['aac56557fb88c5afa94f7c97fc88aa6234e6a19e','276bc30df8f657ffe1cbdc5d0aba68630ec03c5e','2b3b1316d6ec0bbf793ba60ea68a1b656f0c3121']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.501296b9ca200b12"

   strings:
      $hex_string = { 3c392e313645323f28372c313139293a2831372c3078313646292929627265616b7d3b7661722042315130763d7b27453076273a66756e6374696f6e284b2c47 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
