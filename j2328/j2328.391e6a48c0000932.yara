
rule j2328_391e6a48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2328.391e6a48c0000932"
     cluster="j2328.391e6a48c0000932"
     cluster_size="15"
     filetype = "application/xml"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hidelink html script"
     md5_hashes="['07e1e37587abb62ecb95ae714a381c48','2cec61bf9913df13a2fffa49ba614eb5','e8cfce1864f5ea353319115fadeb1a1f']"

   strings:
      $hex_string = { 343235373739333933313727292c6c3d782e6c656e6774683b7768696c65282b2b613c3d6c297b6d3d785b6c2d615d3b0d0a743d7a3d27273b0d0a666f722876 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
