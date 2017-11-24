
rule o2321_6910519cea610912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o2321.6910519cea610912"
     cluster="o2321.6910519cea610912"
     cluster_size="23"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="filetour razy classic"
     md5_hashes="['1e02a1f1fa39a5045b4816ff20d87fe1','2085e618177e7ecc685890e29f16e05b','d24697fa9849a26b126282be4eec956f']"

   strings:
      $hex_string = { 2114aed479e4124293bdea3ac0b08a7ccce8a103c148d7d7fad054f79e84cd58967668f68be3ab807fa5acf4356245d6da2252875d5e3d822859dbd30a448e01 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
