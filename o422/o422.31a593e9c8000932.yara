
rule o422_31a593e9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o422.31a593e9c8000932"
     cluster="o422.31a593e9c8000932"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="jacard delf malicious"
     md5_hashes="['2e3250d25eb3afe9fb738cde307cda763732d706','767e799b10d25a3de1342c36e32ad70a408887ca','da6669da8d82f9b97bf786b9638f17a1fb5327a8']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o422.31a593e9c8000932"

   strings:
      $hex_string = { 457c3e54b5a261665c0dcce5d157691b782850e742487a606dc5f4b21dacb77f9bc3adae040b14a8197358970823058e4d12aff7473a55cb3bab9cbbb6ee4b9f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
