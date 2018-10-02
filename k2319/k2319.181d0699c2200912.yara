
rule k2319_181d0699c2200912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.181d0699c2200912"
     cluster="k2319.181d0699c2200912"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['856ade4c4da620c6ccc24fc5c45a57d31595455d','f003a6239ca32c5c5c7317fbe9f0344c11c0809e','e7a749b78f1185bb25be131b7b12fc7fb9af57c6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.181d0699c2200912"

   strings:
      $hex_string = { 293a2839332c31362e374531292929627265616b7d3b7661722078334d326f3d7b2747367a273a22696a6b222c27543435273a224e222c27483835273a224647 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
