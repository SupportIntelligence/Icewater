
rule m3f2_219a908dc6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f2.219a908dc6200b12"
     cluster="m3f2.219a908dc6200b12"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0cb8b7495e3e43cfc6a956dee7844919','12df3c6fe61ef22a74893bde2d6c3564','f2216f06ca0754e4fa55ee620159d0bc']"

   strings:
      $hex_string = { 29205374657020320d0a46696c654f626a2e57726974652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e65 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
