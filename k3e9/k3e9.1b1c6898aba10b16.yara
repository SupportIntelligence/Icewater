
rule k3e9_1b1c6898aba10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.1b1c6898aba10b16"
     cluster="k3e9.1b1c6898aba10b16"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="neshta hllp neshuta"
     md5_hashes="['4420634200f1d5e8ad2c010bb5594321','493169318dcccd3905bf9e421f522e8a','eb63ce64d7c44c119cc9a75119af5b40']"

   strings:
      $hex_string = { 022c208a57ff88d480ec6180fc19770380ea20b40029d0750580fa0075d25e5fc38d4000979283c9ff31c039f87406f2ae484829c889d7c356e83afbffff89d6 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
