
rule k3f7_2a98a6b9c8800b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.2a98a6b9c8800b32"
     cluster="k3f7.2a98a6b9c8800b32"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html redirector"
     md5_hashes="['392439c18e5ac87826c03117c833cc97','62aa7832941d6c4e302e60a8364b3717','de48d3b41cea195844f18a34f429502c']"

   strings:
      $hex_string = { 343235373739333933313727292c6c3d782e6c656e6774683b7768696c65282b2b613c3d6c297b6d3d785b6c2d615d3b0d0a743d7a3d27273b0d0a666f722876 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
