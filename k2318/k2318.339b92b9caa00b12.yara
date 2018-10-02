
rule k2318_339b92b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.339b92b9caa00b12"
     cluster="k2318.339b92b9caa00b12"
     cluster_size="131"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html redir"
     md5_hashes="['d2f8cf01fdbc1a59072221eeceb155583be3f0b4','7355861b93be0f9150fef45a9e5ad8003b88736d','9aacd78a9cb560c43c62cffa6ae86c1ed5d5f7d0']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2318.339b92b9caa00b12"

   strings:
      $hex_string = { 74642077696474683d223130302522206865696768743d2231342220636c6173733d22696e666f426f7848656164696e67223ed0e0e7e4e5ebfb3c2f74643e0a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
