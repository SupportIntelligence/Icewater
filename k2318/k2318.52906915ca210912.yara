
rule k2318_52906915ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52906915ca210912"
     cluster="k2318.52906915ca210912"
     cluster_size="103"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['f6e2fa05f7ec5d20a6335da7fc739d434985f204','a34d421ee6de9b5d5ffe3c16392b6426e77cd3c3','525a9834eece23b41086ac919c8d7fda135fffc6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52906915ca210912"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
