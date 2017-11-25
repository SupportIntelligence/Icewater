
rule k3f7_490cb6c9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.490cb6c9c8000932"
     cluster="k3f7.490cb6c9c8000932"
     cluster_size="42"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector script html"
     md5_hashes="['05b135b37c32e9d99e39f81e23032c80','0843e5e30a2109b97b389097373b33ee','79b7d3d8558ba38d68cf3c61c4cb6a48']"

   strings:
      $hex_string = { e7bec6b5ead3c5bbddd4a4b6a9b7fecef1a1a322202f3e0d0a3c7374796c6520747970653d22746578742f637373223e0d0a626f6479207b6d617267696e3a30 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
