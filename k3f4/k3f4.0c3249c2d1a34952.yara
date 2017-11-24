
rule k3f4_0c3249c2d1a34952
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.0c3249c2d1a34952"
     cluster="k3f4.0c3249c2d1a34952"
     cluster_size="65"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox msilperseus yontoo"
     md5_hashes="['007639dfc3108d37da48afbd9bd13b11','05ade52ce49d861cb8ae4537fb74c59f','5de0aea97378ddf297ca228dc75d72e9']"

   strings:
      $hex_string = { 72007400750061006c0020006400690073006b000009760062006f0078000007780065006e00008085530045004c0045004300540020002a002000460052004f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
