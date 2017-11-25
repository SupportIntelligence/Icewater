
rule n3e7_2198bab9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e7.2198bab9c2200b12"
     cluster="n3e7.2198bab9c2200b12"
     cluster_size="43"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="downloadsponsor malicious airsoftware"
     md5_hashes="['01d41ad42bb2e79c298c381a58cadb2c','0247d3fbdf790973a6a17fdcf92c2b87','3bca6853e0a2b8fbddfe9efca87a08c6']"

   strings:
      $hex_string = { f070e204bf963696eab403ae1d42da86cbdbacd67da05bb625c712093dc6510fdc3e13ec4b8ec123ebe057219ecaff1120f8ad6df49188a93c060b9c996e4f38 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
