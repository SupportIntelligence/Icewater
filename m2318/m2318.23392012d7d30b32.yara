
rule m2318_23392012d7d30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.23392012d7d30b32"
     cluster="m2318.23392012d7d30b32"
     cluster_size="66"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['04a2b9ce4c796a6e706f4b2d0c8b2800','11c21fbc68d5af300ce596a16cbac2e0','4036fb64757baa090e178230cd9cc86f']"

   strings:
      $hex_string = { 696e672e46696c6553797374656d4f626a65637422290d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c22 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
