
rule n3e9_393173a1c2000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.393173a1c2000b32"
     cluster="n3e9.393173a1c2000b32"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="chir runouce email"
     md5_hashes="['6459691b9095e37330db7c738b71e221','db8a8e22b808a97b374ece60b44ada3e','db8a8e22b808a97b374ece60b44ada3e']"

   strings:
      $hex_string = { 756d41002bccc1e902ffe0e9588bcce8050000007265637600e80c000000636c6f7365736f636b657400e807000000736f636b657400e808000000636f6e6e65 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
