
rule o3f1_491b3949c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f1.491b3949c8000b12"
     cluster="o3f1.491b3949c8000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dowgin androidos inoco"
     md5_hashes="['2dd5885bb7eed3d91d1e56bb360f24f9','340c50f2b2c430e8664e96fb81b1df2a','ebfce2005675287b905c86847be5ef32']"

   strings:
      $hex_string = { 238a424b098e4a028cebb140f23049f9255134159f327a27cf26b2134d78a4c03322316da13acab644e7ea6b72195054f190289964d3566ab5ccadc81f9eac73 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
