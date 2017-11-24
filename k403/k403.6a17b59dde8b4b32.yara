
rule k403_6a17b59dde8b4b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k403.6a17b59dde8b4b32"
     cluster="k403.6a17b59dde8b4b32"
     cluster_size="598"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox netfilter riskware"
     md5_hashes="['0071d0bc0b140595f865619da2b79469','00d8777ecb6f9ffa7ffba2d0e5648ac6','05b9ea22cb085ea5d5cf447fdc180b7d']"

   strings:
      $hex_string = { 8c639d17a308a5abb0fbcd6a62824cd521da1bd9f1e3843b8a2a4f855b90014fc9a776107f27037cbeae7e7dc1ddf905bc1b489c69e7c0a43c3c41003edf96e5 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
