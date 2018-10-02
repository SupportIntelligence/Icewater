
rule k2318_5290796bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5290796bc6220b12"
     cluster="k2318.5290796bc6220b12"
     cluster_size="881"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['e899bd538f9dedae68d6361aacb421db5ab57f14','0507172f9d75361c98e7082d8831f52a0d351096','c47423dbcac9e898efbff776f7d12e0ead60d3c5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5290796bc6220b12"

   strings:
      $hex_string = { 683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a20 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
