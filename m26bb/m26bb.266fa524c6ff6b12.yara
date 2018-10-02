
rule m26bb_266fa524c6ff6b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.266fa524c6ff6b12"
     cluster="m26bb.266fa524c6ff6b12"
     cluster_size="701"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious unwanted vanilloader"
     md5_hashes="['13f1a7c1bb0cafccbfaa8e5c1e184e791ab44df7','374a1294f07afee1dd34ba9d4817034463bb7577','76f2e11b25857c8db8449cdafc799da13e25d77c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.266fa524c6ff6b12"

   strings:
      $hex_string = { 7199fc18729bff18729bff187199fc176f97f6176d94f2166a90e516668bd9156286c6145d7eae1258778f11526f6a0e4159380e0e0e0f3f3f3f067373730200 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
