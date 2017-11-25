
rule j3f7_299a11a1c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f7.299a11a1c2000b12"
     cluster="j3f7.299a11a1c2000b12"
     cluster_size="4"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script expkit html"
     md5_hashes="['659ad0e7411316f20753a8f7943661ce','9b6805eb185a1dc66f9d30bf09dd3538','e1d3f9a36bc49ac88c737ea4efd055e1']"

   strings:
      $hex_string = { 3d200d0a2827303132333435363738394142434445464748494a4b4c4d4e4f5051525354555658595a6162636465666768696a6b6c6d6e6f7071727374757678 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
