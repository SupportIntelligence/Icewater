
rule o3e9_693d9ac9cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.693d9ac9cc000b32"
     cluster="o3e9.693d9ac9cc000b32"
     cluster_size="35"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock yjsx nabucur"
     md5_hashes="['1ea4e580f63dc498537eeeb2e67217ff','24bc0a70e1c98d3e67bed25450ca4689','bcae690ae314102f9c87fff50d40d154']"

   strings:
      $hex_string = { 8091ffab8192ffa2889eff9c8fa7ff939ebaff89accbff71cff8ff74c8f1ff89aacaffb97f85ffcf8962fffed6adfffcd1beffdb968bff331a0d8c351b0e3c3f }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
