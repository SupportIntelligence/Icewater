
rule o3e9_633d1ec9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.633d1ec9cc000b32"
     cluster="o3e9.633d1ec9cc000b32"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock malicious nabucur"
     md5_hashes="['0c285a7e74c9c9b235157018b1c0eaa3','a5b4182014adaade6ecfac0ddd880667','ef617164af36d58bff7711452e150652']"

   strings:
      $hex_string = { 8091ffab8192ffa2889eff9c8fa7ff939ebaff89accbff71cff8ff74c8f1ff89aacaffb97f85ffcf8962fffed6adfffcd1beffdb968bff331a0d8c351b0e3c3f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
