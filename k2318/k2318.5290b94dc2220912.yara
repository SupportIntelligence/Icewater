
rule k2318_5290b94dc2220912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5290b94dc2220912"
     cluster="k2318.5290b94dc2220912"
     cluster_size="482"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['56aacc16f84112c1aec35ad8b7dbf83ae91a85ba','fd4ec8c1ebed727fc6044172a7b7b624f1876a35','5bf3649baa523c989cc73bd05338c8a0b43f1857']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5290b94dc2220912"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
