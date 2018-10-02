
rule k2318_52945acbee210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52945acbee210912"
     cluster="k2318.52945acbee210912"
     cluster_size="635"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['a1fad5c2ab3ad619e9f7ee608fa98f4c754971c5','eeaa5be6ced5c77dc95086d35889e9c783650e92','0db59effcebac3d59f1ddfc2c046bffc8b03588c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52945acbee210912"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
