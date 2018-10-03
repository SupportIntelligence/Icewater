
rule m26d7_12bc5847e83cc65a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.12bc5847e83cc65a"
     cluster="m26d7.12bc5847e83cc65a"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="loadmoney kryptik appl"
     md5_hashes="['9c06dc5ef295e8e2a59bc7cee8a5cad444b8d618','ab497f3f44973a78e4c0baab6916f7268c04ce72','b3caf0cb728226ebd54ac1ceac56a7383d4ea74d']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.12bc5847e83cc65a"

   strings:
      $hex_string = { 9f577eb672437a3b3d851d9c787984c9a5330047815fdc77270f345e4debb05611c02f0097a7135d0c6d1ac6cd2c3155387dee2e488d615bc4f2aeb146ff0869 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
