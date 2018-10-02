
rule k2318_52945adbc2220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52945adbc2220b12"
     cluster="k2318.52945adbc2220b12"
     cluster_size="63"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['2c97a78c6ed3ce640389727f2ec701aafed5f8d3','b5110c05935e7c5d3c68ed25c04785df6e36875d','dd963bd4157cbd3f8e36999b15c6c6c6f63dd2a6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52945adbc2220b12"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
