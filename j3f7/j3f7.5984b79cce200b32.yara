
rule j3f7_5984b79cce200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.5984b79cce200b32"
     cluster="j3f7.5984b79cce200b32"
     cluster_size="8"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="iframe iframem blacole"
     md5_hashes="['346eb56195dc5015409e2b5a9fef537a','3ba3edf15ae456fdb04bfa82876c83cf','fd590f05cce095bd38768e7f5b41658f']"

   strings:
      $hex_string = { 3e0a3c21444f43545950452068746d6c205055424c494320222d2f2f5733432f2f445444205848544d4c20312e30205472616e736974696f6e616c2f2f454e22 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
