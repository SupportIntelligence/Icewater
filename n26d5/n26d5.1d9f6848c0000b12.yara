
rule n26d5_1d9f6848c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26d5.1d9f6848c0000b12"
     cluster="n26d5.1d9f6848c0000b12"
     cluster_size="12"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious genx"
     md5_hashes="['34c0a2e5d75f4867fe8fc8ce75cfd027253cedd8','163ccec5a2963fc82c9bba193255f0e65256dff7','edee1a290912bdab737445b030e96b83d10fec98']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26d5.1d9f6848c0000b12"

   strings:
      $hex_string = { 8b7349d1d37635ccde87bf4f070000500200000000000003de400a05830e7591064c8ffe0e0000a004000000000000f84bbc56975d7e72688d6bd6ac160000f0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
