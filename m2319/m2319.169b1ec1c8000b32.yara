
rule m2319_169b1ec1c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.169b1ec1c8000b32"
     cluster="m2319.169b1ec1c8000b32"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['09080d294804b1ebefcc5f569ad75d86','1a3055224448d12994ae4babc8924f83','fedb943de3efcd193d0ee9f20d808a5c']"

   strings:
      $hex_string = { 2539372d6a756e676c652d6a756d626f2d6a756d70223ee9a39be8b68ae6a3aee69e97204a756e676c65204a756d626f204a756d703c2f613e3c2f6c693e0d0a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
