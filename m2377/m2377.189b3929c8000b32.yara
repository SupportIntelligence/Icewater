
rule m2377_189b3929c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.189b3929c8000b32"
     cluster="m2377.189b3929c8000b32"
     cluster_size="13"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['01bc201999821045fb17f5d3c855da52','054179b3f0c70bff624bfd2d4d76feab','eaaa76ce0c799adf57c16a33f0d69352']"

   strings:
      $hex_string = { ff39e72b4b7551deb68fe2c26892ccc405da4d1774861e97ca24cd99211f12e4d38d4c50151307948bc0e044a8bae67bcd3c03c7c3405df6069c63d6fc9814ad }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
