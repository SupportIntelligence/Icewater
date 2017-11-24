
rule k2377_299f3841c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2377.299f3841c8000b32"
     cluster="k2377.299f3841c8000b32"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="redirector html script"
     md5_hashes="['3fbf9fef3bb74f33137be9bb3b1eb52a','6c463859434e6570d2eaa7a63378d0a5','9b88c60adece65a64bf63443d9971b75']"

   strings:
      $hex_string = { 27313939362d3230303020496e7465722d436f6d707574657220546563686e6f6c6f6779204c74642e273e0d0a3c4d455441204e414d453d2764657363726970 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
