
rule o3f7_1396e448c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f7.1396e448c0000b32"
     cluster="o3f7.1396e448c0000b32"
     cluster_size="323"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['00e359eb715f1c1bf4204bc2ebe8afc8','012023b72d2a1f78363a9569029f92a4','0989b54e2101b2bd6d9a68afb79cbce2']"

   strings:
      $hex_string = { 53c4b04ec4b05a2054c39c524bc4b05945262333393b444520322e20545552204845594543414e493c2f613e0a3c7370616e206469723d276c7472273e283129 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
