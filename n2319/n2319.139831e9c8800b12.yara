
rule n2319_139831e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.139831e9c8800b12"
     cluster="n2319.139831e9c8800b12"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script clickjack"
     md5_hashes="['36a32d2216fc60699ed59aa69d96814623d8f741','bda59835ef63bf589cefdca95fde4b3e3da21131','27694bce24834974aa8cc96830afe27525205ff5']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.139831e9c8800b12"

   strings:
      $hex_string = { 6774687c7c6d2e6572726f722822496e76616c696420584d4c3a20222b62292c637d3b7661722079632c7a632c41633d2f232e2a242f2c42633d2f285b3f265d }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
