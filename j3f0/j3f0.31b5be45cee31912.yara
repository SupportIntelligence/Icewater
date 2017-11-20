
rule j3f0_31b5be45cee31912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f0.31b5be45cee31912"
     cluster="j3f0.31b5be45cee31912"
     cluster_size="46"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious malob"
     md5_hashes="['024b0d17e979b32b8a99f04f6099c9d4','0cc4978d7d1309fe39bfc63c0957a5b5','7d822d27e45bd0bcc6da7f64a586f78f']"

   strings:
      $hex_string = { e48b4d8403483c8b45f00fb740108d4401188945e88b45912b8550ffffff506a008b4584038550ffffff50e8cf07000083c40c8d45f4506a040fb645886bc028 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
