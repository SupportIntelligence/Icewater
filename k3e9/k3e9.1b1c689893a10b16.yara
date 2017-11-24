
rule k3e9_1b1c689893a10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c689893a10b16"
     cluster="k3e9.1b1c689893a10b16"
     cluster_size="972"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp neshuta"
     md5_hashes="['0087649228b8547454fb807f81ba7587','011005d10f116b4b8f3543e624c5ebf7','05bdbee74df150553e8a651d76eb99af']"

   strings:
      $hex_string = { 022c208a57ff88d480ec6180fc19770380ea20b40029d0750580fa0075d25e5fc38d4000979283c9ff31c039f87406f2ae484829c889d7c356e83afbffff89d6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
