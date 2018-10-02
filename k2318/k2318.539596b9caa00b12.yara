
rule k2318_539596b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.539596b9caa00b12"
     cluster="k2318.539596b9caa00b12"
     cluster_size="490"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['c66f504fe30a636f4aaf2c8b49b2017c6b0f3755','d2821723f8fb8ada64bc25230227e71888ef3d43','a22959b3b6334929d2b91c61e661d7822388780c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.539596b9caa00b12"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
