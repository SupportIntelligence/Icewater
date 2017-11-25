
rule o3e9_6e5c3ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6e5c3ec9c4000b12"
     cluster="o3e9.6e5c3ec9c4000b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock tdss nabucur"
     md5_hashes="['2a7d7a9c0b48413fbd2f9eb664515e1e','5164b7007494246b6361dc6618a732d2','ec62a203d88bb52748e7e5f016e016c6']"

   strings:
      $hex_string = { 8091ffab8192ffa2889eff9c8fa7ff939ebaff89accbff71cff8ff74c8f1ff89aacaffb97f85ffcf8962fffed6adfffcd1beffdb968bff331a0d8c351b0e3c3f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
