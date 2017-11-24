
rule k3e9_193e65e355b2f316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.193e65e355b2f316"
     cluster="k3e9.193e65e355b2f316"
     cluster_size="1760"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore dealply unwanted"
     md5_hashes="['00381cefa0b1c4dd50ad176238044fd6','005e2a39a00553ef4da97fd0e35ddd4d','0169bb8cdcef5f13a68401cc4d9282e6']"

   strings:
      $hex_string = { 5077a4a0ce510355ff0ed768a617556e29c4b4ceeaa176a94f001d13327feff98eae8c39bf2bef6959591b11139e23c69bc71921bc22e80cdf72f14b9973e4d5 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
