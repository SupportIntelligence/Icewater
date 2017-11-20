
rule j3f9_21b6fa4f8e611912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f9.21b6fa4f8e611912"
     cluster="j3f9.21b6fa4f8e611912"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious malob"
     md5_hashes="['6c200e69f78748dbeee6179e32a31e47','95155cdec1084a583050b4bb5a6190eb','f2df4a67b6cca56cc48a1fba9910b653']"

   strings:
      $hex_string = { e48b4d8403483c8b45f00fb740108d4401188945e88b45912b8550ffffff506a008b4584038550ffffff50e8cf07000083c40c8d45f4506a040fb645886bc028 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
