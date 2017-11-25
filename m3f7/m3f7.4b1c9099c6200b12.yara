
rule m3f7_4b1c9099c6200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.4b1c9099c6200b12"
     cluster="m3f7.4b1c9099c6200b12"
     cluster_size="252"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['008d22a58f4f28c666a784e69fc1a27e','009fbde5ea9b65fb0a8d04d5ad1547f4','0d67b832742173854dd05f59eaef9912']"

   strings:
      $hex_string = { 6e672e46696c6553797374656d4f626a65637422290d0a44726f7050617468203d2046534f2e4765745370656369616c466f6c646572283229202620225c2220 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
