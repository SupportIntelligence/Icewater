
rule m24c4_2b949518dee30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m24c4.2b949518dee30b32"
     cluster="m24c4.2b949518dee30b32"
     cluster_size="5"
     filetype = "MS-DOS executable (gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['2e4b48e9d62cacbc81a74f00e24f9a28','5e09f3c89a4a3e0854b7f62b4fb1fe93','92a40bc225e0034fe0c72d35afe2d5cb']"

   strings:
      $hex_string = { 3a500822ca0914aaf96cb1d72419630b9315f647b2608c7002f35a1e135bcc75b6b0f3c47b1b5ffc236d9bcb9ce2664cd29fda829273fadb76054bd588844a26 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
