
rule n26d5_59d46a4cc0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.59d46a4cc0000b12"
     cluster="n26d5.59d46a4cc0000b12"
     cluster_size="54"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['464bafeb6ce8246be03f77924c7ee99053a998c0','6c0d1e62039255c155a45a6e994946814f1a51d0','ea61d42889fb90e6c45ae21abe08dda24eba2413']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.59d46a4cc0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
