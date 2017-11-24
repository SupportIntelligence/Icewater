
rule k3e9_1b1c689885a91b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c689885a91b16"
     cluster="k3e9.1b1c689885a91b16"
     cluster_size="507"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp neshuta"
     md5_hashes="['011cfea294a901476db22e419f48a972','01c8105c9f26f185e809e6000a36b926','0b30cdf5064279ea0f70f3869594383e']"

   strings:
      $hex_string = { 022c208a57ff88d480ec6180fc19770380ea20b40029d0750580fa0075d25e5fc38d4000979283c9ff31c039f87406f2ae484829c889d7c356e83afbffff89d6 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
