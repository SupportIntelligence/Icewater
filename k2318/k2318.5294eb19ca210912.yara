
rule k2318_5294eb19ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5294eb19ca210912"
     cluster="k2318.5294eb19ca210912"
     cluster_size="386"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['a712ceb90cb1e1a1cdd079216e5096ddd0baf5d3','91758cf9ef1822a168ec04c1a91c9a68e220a344','4cf7cbc5decd7e154bdbc31c5e063b8260bdd55f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5294eb19ca210912"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
