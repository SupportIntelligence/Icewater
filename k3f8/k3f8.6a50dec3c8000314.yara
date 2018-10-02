
rule k3f8_6a50dec3c8000314
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f8.6a50dec3c8000314"
     cluster="k3f8.6a50dec3c8000314"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos origin"
     md5_hashes="['8d73f3cd716a72f26bbf731ff2d9472c4b273d4c','c09a70db5935465e7c49902c6a900befddae5b48','05ed7af10a33bad85f65ee95d2ffc6078b9c4325']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k3f8.6a50dec3c8000314"

   strings:
      $hex_string = { 642f6170702f496e74656e74536572766963653b00224c616e64726f69642f6170702f4e6f74696669636174696f6e244275696c6465723b001a4c616e64726f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
