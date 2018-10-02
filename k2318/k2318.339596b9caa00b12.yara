
rule k2318_339596b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339596b9caa00b12"
     cluster="k2318.339596b9caa00b12"
     cluster_size="284"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['cc5b8d4bbb19639f92b0f09fdaccb1cb5bce26cb','e6f96ea500d7c6580a9212f1c97c07bf4f2ca57c','49e1ab75cb30b15f0242a420faa8dfd514e1b212']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339596b9caa00b12"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
