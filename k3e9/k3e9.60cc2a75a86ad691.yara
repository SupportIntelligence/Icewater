
rule k3e9_60cc2a75a86ad691
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.60cc2a75a86ad691"
     cluster="k3e9.60cc2a75a86ad691"
     cluster_size="11"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vbna chinky vobfus"
     md5_hashes="['16be16ed46090f285590f0e35ad5fdb6','4935b84c613721585e2545438bfc5a3e','dbb1acd9b07b13a36fc13bd80e4d1804']"

   strings:
      $hex_string = { 0d4c0705006c64ff2a235cff0460fff4012b70ff0503002404000d500705006c60ff2a2350ff0454fff4012b5aff0503002404000d4c0705006c54ff2a2344ff }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
