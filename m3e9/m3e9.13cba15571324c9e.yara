
rule m3e9_13cba15571324c9e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13cba15571324c9e"
     cluster="m3e9.13cba15571324c9e"
     cluster_size="129"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shipup kazy kryptik"
     md5_hashes="['075d763488430a68f38d445ae8419105','12f3383819c5a690ec546218353bd06b','6bbdb0315cdcf0e8bb248869ee51b7a0']"

   strings:
      $hex_string = { 988e6723b4826b27b0865f2bacfa631fa85e5713c4525b77bf564f7bbb4a536fb7ee4783d3e24b87cfe63f8bcbda437fc7fe3773e3f23b97dff62f9bdbea338f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
