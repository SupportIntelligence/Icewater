
rule k2318_5294eb89ca210b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5294eb89ca210b12"
     cluster="k2318.5294eb89ca210b12"
     cluster_size="188"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['24743ed95f0d25d5163a06a2d022998278e6a7ef','42ae71c5979e97f919d61ce9c958a157c56e03e5','707aac4db9c0b9568578ad267dfd11d48c5e53ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5294eb89ca210b12"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
