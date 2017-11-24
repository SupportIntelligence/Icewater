
rule k24c1_5336b29d96fb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k24c1.5336b29d96fb0912"
     cluster="k24c1.5336b29d96fb0912"
     cluster_size="4"
     filetype = "Dalvik dex file version 035 (Zip archive data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos smssend trojansms"
     md5_hashes="['2ca1ea0e49ab90900c812c37bfab7265','3550888fcbfaa0ab11368410025889ff','e0dd60550d0a66fc8e0f51f5443e9cc2']"

   strings:
      $hex_string = { 0b70bc3e9c47941eb46f5331ebadc7bf6133e4b8a1ed2664c0dae3738781b1a4dee6300a168f9e6dab3a7f4df70539b9d04a652db1f785ea9af4f3fbd2cae882 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
