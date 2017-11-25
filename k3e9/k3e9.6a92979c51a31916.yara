
rule k3e9_6a92979c51a31916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.6a92979c51a31916"
     cluster="k3e9.6a92979c51a31916"
     cluster_size="4566"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vittalia malicious unwanted"
     md5_hashes="['00162c69f4273509f9847ca494043259','0035c6b6306c59a299b8eadf9edf3480','01af044c79227188e06b3be430a1d2a5']"

   strings:
      $hex_string = { 07457e4ce75f4adb7f52177225aa428af20cf212fadffb08fd980ea488320f99705457349066c416e6d4d04ff5b7cf5615cba2d928add23ce531b291cd274e04 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
