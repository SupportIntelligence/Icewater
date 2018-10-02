
rule k2318_5394eb19ca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.5394eb19ca210912"
     cluster="k2318.5394eb19ca210912"
     cluster_size="367"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['801fefb0960a1f104ab38e8d4b6f420d4246bfe5','5b1d2e99f75c0f5b02712bf6749f4e3f1f0c3507','c1a48b2a4e0cf67963989916b360202c0ece967f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.5394eb19ca210912"

   strings:
      $hex_string = { 74683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ecff0eee8e7e2eee4e8f2e5ebe83c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
