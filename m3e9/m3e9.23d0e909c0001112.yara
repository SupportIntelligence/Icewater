
rule m3e9_23d0e909c0001112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.23d0e909c0001112"
     cluster="m3e9.23d0e909c0001112"
     cluster_size="13935"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik doxv"
     md5_hashes="['00169647221d220ce2e4cc205ea9b9f6','002111dfac3361d093f6eb1b4ffa0f1a','011a3cdbd1bd1c7db608df57d056bfd1']"

   strings:
      $hex_string = { 45f85a89400889400483c0084a75f46a048bfb6800100000c1e70f03790c680080000057ff1554a0400085c0750883c8ffe99d0000008d97007000003bfa8955 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
