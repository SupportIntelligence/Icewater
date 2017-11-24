
rule m2377_731f2008d9eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.731f2008d9eb0912"
     cluster="m2377.731f2008d9eb0912"
     cluster_size="8"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['1b264b5ce4f509609ed18a54b191da61','2acf670bbe09a5b5b780914c71de4b68','c2b56b0035b1bd691db9dce7dad860bd']"

   strings:
      $hex_string = { 652043687228434c6e6728222648222026204d6964285772697465446174612c692c322929290d0a4e6578740d0a46696c654f626a2e436c6f73650d0a456e64 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
