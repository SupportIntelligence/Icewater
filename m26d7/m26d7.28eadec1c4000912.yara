
rule m26d7_28eadec1c4000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26d7.28eadec1c4000912"
     cluster="m26d7.28eadec1c4000912"
     cluster_size="77"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="unwanted heuristic hfsadware"
     md5_hashes="['d9c7c9ff935567ad2281c424d7287b7d2f33433e','8ea0f5893795632a8738ebea005bb1d983a334d5','42e5c646dfab4caddecc14cd6f0f723c512b7f35']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26d7.28eadec1c4000912"

   strings:
      $hex_string = { 6909ead56acc6d0b11bce8574841a9c691015ab2f3a58a4e72cae6c32b4488a46fb0db8035a3d95f95fabe387948a6ce824cf52d609f83b296b1b4ba1a10b69c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
