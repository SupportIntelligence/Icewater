
rule k2328_6abb7949c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2328.6abb7949c8000932"
     cluster="k2328.6abb7949c8000932"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="iframe html iframeref"
     md5_hashes="['92272777c03f60929104ba19efa6cc7c8c711637','1b7ca288aa35474b88bda780df16807766f3b086','04de94dbed93372d9b141ecae18abf928d133172']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2328.6abb7949c8000932"

   strings:
      $hex_string = { 3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d2269736f2d383835392d32223f3e3c21444f43545950452068746d6c205055424c4943 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
