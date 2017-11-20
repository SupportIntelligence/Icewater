
rule m3e9_13ea7b4940000916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.13ea7b4940000916"
     cluster="m3e9.13ea7b4940000916"
     cluster_size="1477"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted bundleinstaller"
     md5_hashes="['00750860835d77da6315fba85656ea43','0082ff654499d26d0e8e191a3bf73c2b','040db66c6d110ceeb57d8f0ddb967e9b']"

   strings:
      $hex_string = { cd7d9ba703a49fdbf48221522923de72cb663bf3e3c6705700afd7f8ed7418a5353ff68438b5c580b8b26dc76f1017985a49918c0a1ed2126eb9ee16f5931a81 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
