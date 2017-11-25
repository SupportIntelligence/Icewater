
rule k3f7_490db6c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.490db6c9c8000932"
     cluster="k3f7.490db6c9c8000932"
     cluster_size="27"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['0508342523a2e1034267b4394381064c','05219aea0a3a629d2d3f5dcb2a8233e7','93eb4eca55c71c0dbc7c00cd8c139ecf']"

   strings:
      $hex_string = { e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
