
rule m3f7_61b4b408d9bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.61b4b408d9bb0912"
     cluster="m3f7.61b4b408d9bb0912"
     cluster_size="426"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['004f29a9769db158ea730032cec399a6','009b7551ab7d8a6add65e3dafab00cdc','0b5d47a1e186ba6e9dc35b3df06b2072']"

   strings:
      $hex_string = { 654f626a6563742822575363726970742e5368656c6c22290d0a5753487368656c6c2e52756e2044726f70506174682c20300d0a2f2f2d2d3e3c2f5343524950 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
