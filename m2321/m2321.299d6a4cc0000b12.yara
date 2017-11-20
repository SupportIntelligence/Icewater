
rule m2321_299d6a4cc0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.299d6a4cc0000b12"
     cluster="m2321.299d6a4cc0000b12"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['55f7e1fd5470dbd16991627db408c3a4','5ccecf3607caa07e562af228fd60fd23','d51ddb929c5330a112282077743bc726']"

   strings:
      $hex_string = { 98aa4c4fcc57b8515ce072d27b462cbb8f238a831e056c961cf7a741a109b55f1b6704e8d087a7c9e491b009926805d36442b9bdf33660a9a3bfd4ec6b772697 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
