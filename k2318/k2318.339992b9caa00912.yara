
rule k2318_339992b9caa00912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339992b9caa00912"
     cluster="k2318.339992b9caa00912"
     cluster_size="615"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['690364c745fa6fc6ac4497845bb9b77ec85cecce','8ae2a5d1a4776ac83c0e041e33ebd7dc8c53666b','9130e2cdc871715b1572e9bd82a55c6129e863a7']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339992b9caa00912"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
