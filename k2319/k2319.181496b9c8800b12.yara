
rule k2319_181496b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181496b9c8800b12"
     cluster="k2319.181496b9c8800b12"
     cluster_size="20"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['6bfc66b3941351a2d6644c171ea5bcd99e39d36b','d6472f9503f8249a43742cf255cbca6b146bd156','efdfbd6a7cc5f8166a23872c35ceaf9c4af440ca']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181496b9c8800b12"

   strings:
      $hex_string = { 213d3d756e646566696e6564297b72657475726e206a5b4c5d3b7d76617220443d28307831443c28382e383445322c39362e293f28342e353145322c30786363 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
