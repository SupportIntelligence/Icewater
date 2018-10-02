
rule k2318_739992b9caa00912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.739992b9caa00912"
     cluster="k2318.739992b9caa00912"
     cluster_size="2510"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['f7b1b2e6fdaac0e0aaf843ab16966e83362fccf0','a600532d2fc921cf0baf9360e5de6c1a5f854ac7','c33c77688e8293283dc80adadd841b50174c5b25']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.739992b9caa00912"

   strings:
      $hex_string = { 642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
