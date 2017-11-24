
rule m2321_291c94b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.291c94b9c2200b12"
     cluster="m2321.291c94b9c2200b12"
     cluster_size="16"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['07c3118cfa6b88dc2fc970547b88c603','0b3de45393636e1447a14dec02495c07','fd63a99cdfd70873492c743a4e3d36c9']"

   strings:
      $hex_string = { 6eab645e97d5b541ca562ed9e8ccc5cf17986de63ac7932d3fdb69b06fb4892b555b7662b8652746575afa32d138264ed3354c07348800e3b19458742a2acee7 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
