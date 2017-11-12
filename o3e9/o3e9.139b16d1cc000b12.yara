
rule o3e9_139b16d1cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.139b16d1cc000b12"
     cluster="o3e9.139b16d1cc000b12"
     cluster_size="326"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['015ebae3ecd05aaf3345f64aea5080f8','0272bb1f031e5adbb7fcc51b857e1088','091ad3732a787ab278b3eeb47d4d0102']"

   strings:
      $hex_string = { 1fe2377feb77b8f7be7b999a9ce4de132736ae3f6e03c9454883763b1ebd923e8544fe00914f4093844e6bd5494722f2629bed09679814c4fb53b7ab304265b4 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
