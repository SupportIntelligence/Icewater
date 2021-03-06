
rule k3f7_491294c986220b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.491294c986220b32"
     cluster="k3f7.491294c986220b32"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="fakejquery script classic"
     md5_hashes="['bfab2109787723d8471eefcb8f4eda91','dd599cd86bb4daf95b18e92df53556b9','e749a53b2968921f7a03acd7038f42a1']"

   strings:
      $hex_string = { 6d6528292b36302a632a36302a316533293b76617220653d22657870697265733d222b642e746f555443537472696e6728293b646f63756d656e742e636f6f6b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
