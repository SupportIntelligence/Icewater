
rule k3e9_09346de159b2e316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.09346de159b2e316"
     cluster="k3e9.09346de159b2e316"
     cluster_size="41"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore unwanted browsefox"
     md5_hashes="['045ffb8bf0a75cd6a232361b4ad1393d','1a5edf7b5a2d6a3a4354f3a4b19dd97e','7e758f54d763b50ae209caf929d459be']"

   strings:
      $hex_string = { 5077a4a0ce510355ff0ed768a617556e29c4b4ceeaa176a94f001d13327feff98eae8c39bf2bef6959591b11139e23c69bc71921bc22e80cdf72f14b9973e4d5 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
