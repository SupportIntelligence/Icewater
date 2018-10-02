
rule n3f8_6aa38c468ee31114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.6aa38c468ee31114"
     cluster="n3f8.6aa38c468ee31114"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos trojansms smforw"
     md5_hashes="['33369353bc55411d4aa1e1268afd8690cb57ceba','13ff22e12efa4c59eaa6af8eaa825ba9e5eb3eed','d2c20d8536ac9e22ab7f874cd8719985458a507e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.6aa38c468ee31114"

   strings:
      $hex_string = { 5f4e4f4e45000d5452414e5349545f554e53455400214c616e64726f69642f737570706f72742f76342f6170702f467261676d656e743b00034c494c00124c6a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
