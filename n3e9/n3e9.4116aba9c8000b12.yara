
rule n3e9_4116aba9c8000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.4116aba9c8000b12"
     cluster="n3e9.4116aba9c8000b12"
     cluster_size="126"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['06a5c9e6501918d6221b44a90821552b','06edf1162f76df22ef59330810f369c8','68578fe0d657324214a92451c4e40610']"

   strings:
      $hex_string = { bc92735cf9b9e64c150a23cce4d2d4342e4940153c0f607a24c6a566ef96cf70eb3ee7f40d7edcd17ca3767169c19c4f47303521b1a2af1a623c2bd98eaa2a07 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
