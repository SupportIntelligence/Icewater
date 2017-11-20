
rule m2318_52db200084314c9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2318.52db200084314c9a"
     cluster="m2318.52db200084314c9a"
     cluster_size="4"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['13d4c589e780cbb2b16b4871c7744945','3225bf8878abbd7ae73874bac5cf126c','6e53283db87b249caade80c11b8377ee']"

   strings:
      $hex_string = { 88c39bb496b973cd4ac7a259b871090447aff453b1f8926adfa4520bdde64d543f3f8be67cf1802e21dcf42c5b623fd069cdb06734297310357456ad95e0bf25 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
