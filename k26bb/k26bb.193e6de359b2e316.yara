
rule k26bb_193e6de359b2e316
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bb.193e6de359b2e316"
     cluster="k26bb.193e6de359b2e316"
     cluster_size="24"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious unwanted"
     md5_hashes="['3d6d6f8398bae0403a404623e9d22b1443f0af02','fa2cdd48771476af1b3ec5172aafd97adbdb4daa','a72894859a297e2b4092acc5eb517e9bb94c9b41']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bb.193e6de359b2e316"

   strings:
      $hex_string = { 0380eb208a7fff80ff61720880ff7a770380ef2038fb74d80fb6c30fb6d729d05b5f5ec39083c4f86a0089442404c6442408008d4c24048bc2bac04c4000e8f6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
