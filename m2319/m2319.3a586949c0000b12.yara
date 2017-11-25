
rule m2319_3a586949c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.3a586949c0000b12"
     cluster="m2319.3a586949c0000b12"
     cluster_size="6"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script trojandownloader"
     md5_hashes="['18e0cd374c75fc37c54fb31db7661225','1ee3051f542e23c1f12b2fd3575cb3b3','e09e9a0edaa4236831f457f8363772cd']"

   strings:
      $hex_string = { 2428276963657461627334323227293b200a09766172206f626a656374203d206e6577204c6f66536c69646573686f7728205f6c6f666d61696e2e676574456c }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
