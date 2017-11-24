
rule m2319_3a596949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3a596949c0000b12"
     cluster="m2319.3a596949c0000b12"
     cluster_size="5"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['595706456eed6c367e4b364e3a725c90','7adbcc5321a051c29778406b0f59349b','ebb7a18c33c9120a7c9660616c93265d']"

   strings:
      $hex_string = { 2428276963657461627334323227293b200a09766172206f626a656374203d206e6577204c6f66536c69646573686f7728205f6c6f666d61696e2e676574456c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
