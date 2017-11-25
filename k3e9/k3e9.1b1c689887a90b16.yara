
rule k3e9_1b1c689887a90b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c689887a90b16"
     cluster="k3e9.1b1c689887a90b16"
     cluster_size="3959"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp neshuta"
     md5_hashes="['001978110e2fd9b09251bee04175bebf','001f6d3fe070800f044380740edb1f25','0134cef85a86a3cd0ed1afd26f54d133']"

   strings:
      $hex_string = { 022c208a57ff88d480ec6180fc19770380ea20b40029d0750580fa0075d25e5fc38d4000979283c9ff31c039f87406f2ae484829c889d7c356e83afbffff89d6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
