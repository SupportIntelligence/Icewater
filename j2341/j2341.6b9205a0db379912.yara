
rule j2341_6b9205a0db379912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2341.6b9205a0db379912"
     cluster="j2341.6b9205a0db379912"
     cluster_size="9"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="derl hacktool rabased"
     md5_hashes="['09cbf13c5c2e6570b86337ef1bc1d59c','44f0e486c2846f62f8d388ba611e47aa','c392522a7ef1dd1cf9d2ce94005f8243']"

   strings:
      $hex_string = { 35332c36352c37342c30382c30302c5c0d0a202030300d0a22465553436c69656e7450617468223d22433a5c5c50726f6772616d2046696c65735c5c52656d6f }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
