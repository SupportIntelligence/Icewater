
rule m2321_4d1b1ec1cc000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.4d1b1ec1cc000b32"
     cluster="m2321.4d1b1ec1cc000b32"
     cluster_size="78"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['017e1b0460c475be23d5c0b5c7f87967','0283fd8fd23d84004316410ecfbd5f8e','2f9526b075167274cc022f3809bd4b66']"

   strings:
      $hex_string = { 57c58b02dca9c4adbba505d4ccf17e5c9af7ea9054b43b75c3ae3d360ec0a845682265481e9fcb0a79f5b260aa919d38ca19a24624bfdf3f4e32e94b6ab592dd }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
