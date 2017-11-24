
rule m231b_4b16586398bb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.4b16586398bb0912"
     cluster="m231b.4b16586398bb0912"
     cluster_size="35"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink script html"
     md5_hashes="['0030e019cb6a61defafbd8619dfff55a','0b034a1e0b3f9a87cef4fe4830acc6d3','47eb76443b2b2ca94a835bcafa96cf8f']"

   strings:
      $hex_string = { 696e672e66726f6d43686172436f6465287061727365496e742874292b32352d6c2b61293b0d0a0d0a743d27273b7d7d785b6c2d615d3d7a3b7d646f63756d65 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
