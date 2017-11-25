
rule m3e9_5db28adaee57d131
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5db28adaee57d131"
     cluster="m3e9.5db28adaee57d131"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious suspected unwanted"
     md5_hashes="['617c75a749ddf5ccc6f9cdbe74b138a7','66a867bec616edcb60835a545c451750','e4874337b67be7569a1e2b59fef76c42']"

   strings:
      $hex_string = { 912a004cf08f62303778a38427076f18b2de25dca0d49403aa864e259f9a40031cddcee379cb216806dab632b46dbff42c266333e449646d0de6c3670ef705a4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
