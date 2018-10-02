
rule k2318_739b92b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.739b92b9caa00b12"
     cluster="k2318.739b92b9caa00b12"
     cluster_size="1430"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['65ba8baa685665dbaf07164dfcc5145b1d05b492','b9777ac28d89831b5ffb5e975944851b9bdebe7d','0d79f0f6f74dec4820bc7c6ced1bba30493a8603']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.739b92b9caa00b12"

   strings:
      $hex_string = { 642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
