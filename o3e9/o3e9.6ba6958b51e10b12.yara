
rule o3e9_6ba6958b51e10b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.6ba6958b51e10b12"
     cluster="o3e9.6ba6958b51e10b12"
     cluster_size="372"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob classic"
     md5_hashes="['01ee2b8e99d173b41ff36e775fbda95e','02ec328abb57dc7f27bb07b87fa1d9ba','15cdee8f5c2d014b99b95fe7bcae2dfb']"

   strings:
      $hex_string = { 3349e82cffcd52b611514446fd80d1bec1a82f09f6e2a29e4f585e534784435a948ba6393d196f0cd8bb38a3de88acdffb0027f45916129825015d503b455c95 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
