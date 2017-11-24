
rule m2321_2b949518dee30b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.2b949518dee30b32"
     cluster="m2321.2b949518dee30b32"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['1cda01ad648c51362db4f672d8335802','26ade599313091a168c6aa82d88a5489','d5014bc1f31a1bc3437b48b8667f9c5b']"

   strings:
      $hex_string = { 3a500822ca0914aaf96cb1d72419630b9315f647b2608c7002f35a1e135bcc75b6b0f3c47b1b5ffc236d9bcb9ce2664cd29fda829273fadb76054bd588844a26 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
