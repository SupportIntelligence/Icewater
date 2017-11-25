
rule k3e9_5b1c689cb6610b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.5b1c689cb6610b16"
     cluster="k3e9.5b1c689cb6610b16"
     cluster_size="196"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta nestha hllp"
     md5_hashes="['00fafc2e398b11390e3b97e9d5c13aa9','018ad57c4e3bbb9780ee1ed3c799a8e4','13b1302e8d7ff37e3723a5183a3f4383']"

   strings:
      $hex_string = { 022c208a57ff88d480ec6180fc19770380ea20b40029d0750580fa0075d25e5fc38d4000979283c9ff31c039f87406f2ae484829c889d7c356e83afbffff89d6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
