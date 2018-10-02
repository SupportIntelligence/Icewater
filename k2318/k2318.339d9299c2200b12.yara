
rule k2318_339d9299c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339d9299c2200b12"
     cluster="k2318.339d9299c2200b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redirector"
     md5_hashes="['c871909f9e6c07182eb75753544993ac159ceacb','5b16b234c79c6909c498a90c6b4d9cd7bc7bd013','853a632153e1db6b509c3a3d29dc418d9b0d0ec4']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339d9299c2200b12"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
