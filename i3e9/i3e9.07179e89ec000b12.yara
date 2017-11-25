
rule i3e9_07179e89ec000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3e9.07179e89ec000b12"
     cluster="i3e9.07179e89ec000b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="cosmicduke backdoor razy"
     md5_hashes="['050f16af199d37365c51b1a635de1b27','3d88bc5a26ab90cfc78a7073afbdadde','e332950136f03552d2b79f3383580b12']"

   strings:
      $hex_string = { 576f9e2985a9c9d1898d78bd7ba2f2c2f862a571b158ae2d56462fc49ecb69ec9938bbe3958b69e0f048314e70a3c55a9c711cebe87c6db6d24817125b4c1e1b }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
