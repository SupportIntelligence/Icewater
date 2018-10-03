
rule k2318_311248cebe210932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.311248cebe210932"
     cluster="k2318.311248cebe210932"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="redirector iframe html"
     md5_hashes="['9fe6201df834281c827d5926050b936b8c31ca6d','b7b899656b0d79cb51c6199aaa06f0bf603bb814','513b029b984e3f40bf39ed003dba12c9d8320169']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.311248cebe210932"

   strings:
      $hex_string = { 75626d697428293b222073697a653d223122207374796c653d2277696474683a2031303025223e3c6f7074696f6e2076616c75653d22222053454c4543544544 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
