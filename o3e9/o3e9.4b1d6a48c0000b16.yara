
rule o3e9_4b1d6a48c0000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4b1d6a48c0000b16"
     cluster="o3e9.4b1d6a48c0000b16"
     cluster_size="21"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock vpii nabucur"
     md5_hashes="['0b5c10add670b77e8c78f4316fc64ab0','22ecd792df68befdaf824c9af0e5dd5d','d9ea05f172d1e95e172e30ad0cd9cf26']"

   strings:
      $hex_string = { 3e02fbfbf97994a8f2ff0838f5ff325bfeff5376feff738efeff8ba3f8ffa4b4ecffb6bcdfffbcc6d4ffafd7caff8edcbeff4ad29cff0fbc79ff00a76bff0398 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
