
rule o3e9_0b3151d2940af192
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.0b3151d2940af192"
     cluster="o3e9.0b3151d2940af192"
     cluster_size="691"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmonstr malicious dlboost"
     md5_hashes="['002e5e6698976267f98edcb95c5bcb92','003f564d41cc90abf114644f648d04b1','05707b0c0190d0ea78e34a234dad2a03']"

   strings:
      $hex_string = { 5a0e17caddab424ec534bd863f5848509ead89683a8fcd8bdeaa14558166d3e329b16e3974536d134122c0085f7f0665bfa4e5c88798f0f88efea9d2a6ae9611 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
