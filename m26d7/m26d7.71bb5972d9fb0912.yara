
rule m26d7_71bb5972d9fb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.71bb5972d9fb0912"
     cluster="m26d7.71bb5972d9fb0912"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['6d56948a80d3340b82fe3ab179fddb0c0b9e874f','8249f70e4b7f64e0e32b413fd0de040b8d4e0d6a','9bcfa6e79a0fe04b5d6b471aa694ce58bf019afa']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.71bb5972d9fb0912"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
