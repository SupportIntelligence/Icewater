
rule k2318_739992b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.739992b9caa00b12"
     cluster="k2318.739992b9caa00b12"
     cluster_size="1940"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['19af43e4f26f9cf7e8ec4b6cf9f0160c1230adf4','8121e5c25930f8b21775aee3b9340f2b25d46bfa','81ae0ef04de85d98bda702b02b14938925648a81']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.739992b9caa00b12"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
