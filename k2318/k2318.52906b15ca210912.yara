
rule k2318_52906b15ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.52906b15ca210912"
     cluster="k2318.52906b15ca210912"
     cluster_size="419"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe redir redirector"
     md5_hashes="['cba8466656a2cb1b0df0e5ee772356ac99f761ac','bc6b57293969d2e4922cc0317979835e4632dced','45e7a1b37844a2ace834d9c5e1d18adf50d2d080']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.52906b15ca210912"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
