
rule i3ed_291f5b4f2ba10b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.291f5b4f2ba10b12"
     cluster="i3ed.291f5b4f2ba10b12"
     cluster_size="90"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="debris gamarue zusy"
     md5_hashes="['05b5ee87ed947c1fb4dfc0526c44f96c','0626016f1122e7328946d4fea150a66f','3d7631ed38275552ef4e13907f06788a']"

   strings:
      $hex_string = { 85c0740f8b4d088a1180c2018b45088810ebde5dc3cccccccccccccccccccccc558bec518b450c8945fc837dfc017402eb0d6800300010e8a4ffffff83c404b8 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
