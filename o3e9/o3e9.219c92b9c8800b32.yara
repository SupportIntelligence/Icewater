
rule o3e9_219c92b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.219c92b9c8800b32"
     cluster="o3e9.219c92b9c8800b32"
     cluster_size="19"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="miniduke backdoor cosmicduke"
     md5_hashes="['20da85a976ac80640301e8ecce5e7a7b','226c90b4008285213a928ae9f663548a','d76a3ef9bbc1194a3420ccf8c12769b8']"

   strings:
      $hex_string = { f9851ef07a6a2bb5f2bcf1cc5e0dcbefd9a5126bd73f0c4748c97781ba45b40fbf3ed51c98515a0a20fc51e086fe3ab17655a3a910b61f2d05dcbbe626581bea }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
