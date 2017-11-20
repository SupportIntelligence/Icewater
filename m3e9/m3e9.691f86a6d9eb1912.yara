
rule m3e9_691f86a6d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.691f86a6d9eb1912"
     cluster="m3e9.691f86a6d9eb1912"
     cluster_size="33"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal viking wapomi"
     md5_hashes="['3a5fe0be5082c95b7196282e1b3e635d','3fc05b714d832e55d4623f3eebc5b396','baafc789f64c9933234ae579e639ff0a']"

   strings:
      $hex_string = { 6e560a1fe554a4e782c6ea6a9d0e995275152da863b6ffe4b09102a5afc33208f847091aa6a39a68d5b57a14e2bd408cf7d861ba5d2a0d4f8195aef520a9c5a2 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
