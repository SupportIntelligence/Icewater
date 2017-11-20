
rule m2377_63b92012d3d30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.63b92012d3d30b32"
     cluster="m2377.63b92012d3d30b32"
     cluster_size="509"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['01299c601ea7894245b29de438983c3f','01c7d1895d2683e36677af68ffa2646b','0b9d7820b4660ba88aa11239ff6692e0']"

   strings:
      $hex_string = { 6369616c466f6c646572283229202620225c2220262044726f7046696c654e616d650d0a49662046534f2e46696c654578697374732844726f7050617468293d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
