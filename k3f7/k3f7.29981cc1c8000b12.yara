
rule k3f7_29981cc1c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.29981cc1c8000b12"
     cluster="k3f7.29981cc1c8000b12"
     cluster_size="14"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script html redirector"
     md5_hashes="['05451beaee1e8a5abeaebe2e9cf4ccaf','0ef8fdf9ada763daebda90f132b5f194','fc33dfa61db6980cee33e450738abdfb']"

   strings:
      $hex_string = { 3d200d0a2827303132333435363738394142434445464748494a4b4c4d4e4f5051525354555658595a6162636465666768696a6b6c6d6e6f7071727374757678 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
