
rule n26d5_2d9fea48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.2d9fea48c0000932"
     cluster="n26d5.2d9fea48c0000932"
     cluster_size="57"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['8efecb8732381a8c010ce9e13a60818aef01b3ac','d77084379cb749ad2d7efb3c175c5aca4910e081','1f99873aef5c9f2b97289bfc3d0830e58bc61a33']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.2d9fea48c0000932"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
