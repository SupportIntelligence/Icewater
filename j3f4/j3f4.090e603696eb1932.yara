
rule j3f4_090e603696eb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f4.090e603696eb1932"
     cluster="j3f4.090e603696eb1932"
     cluster_size="4"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy malicious revenge"
     md5_hashes="['646705f3cdb92a900c4439c7db9b7cfb','c9912f044d4cb0844fc553d1797cd544','f71e4c1c4f0f5ed53db01987bdfb8656']"

   strings:
      $hex_string = { 000000efbbbf3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d3822207374616e64616c6f6e653d22796573223f3e0d0a3c }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
