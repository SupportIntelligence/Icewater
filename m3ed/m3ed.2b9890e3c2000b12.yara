
rule m3ed_2b9890e3c2000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ed.2b9890e3c2000b12"
     cluster="m3ed.2b9890e3c2000b12"
     cluster_size="7"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="sality crypt salpack"
     md5_hashes="['22a4465097e91e92cbbc2d33850a74a1','5d1080feda6fd58667d6cd2334e59a1b','f4b8b1bac4f17495c09e346c8b22f3d3']"

   strings:
      $hex_string = { 00e001004000000085379937b437ce37db37ed37fa370e3814381a382738353840384d3873389738a438b138b938bf38cc38eb380f391c392939ae39be390000 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
