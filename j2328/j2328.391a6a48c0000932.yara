
rule j2328_391a6a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2328.391a6a48c0000932"
     cluster="j2328.391a6a48c0000932"
     cluster_size="95"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="hidelink html script"
     md5_hashes="['a0c72f37836f554492d47f40f71d39258b8831ae','ff40562df69d453bb752051c7c0fe7fa4c0b430f','613198d0c711dcf5a06c781b038e77ab54c6146c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j2328.391a6a48c0000932"

   strings:
      $hex_string = { 343235373739333933313727292c6c3d782e6c656e6774683b7768696c65282b2b613c3d6c297b6d3d785b6c2d615d3b0d0a743d7a3d27273b0d0a666f722876 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
