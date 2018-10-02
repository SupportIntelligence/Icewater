
rule k2318_339a97a9c8800912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339a97a9c8800912"
     cluster="k2318.339a97a9c8800912"
     cluster_size="729"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['731a519efb0120fc650a30545d98493ab60ead66','5e3d0844bd10acac8f77d120d9ca7c28bf3d3ccc','793987773b0848dd46241ad8442fd3b2c40a1dd2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339a97a9c8800912"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
