
rule m3f7_52db200884314c9a
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.52db200884314c9a"
     cluster="m3f7.52db200884314c9a"
     cluster_size="84"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0074e044eb1031643beb0d66694fab2a','007fdded4fd5431efbf0a9325a326fc7','2d4f1655326e15a90852d19da4af1394']"

   strings:
      $hex_string = { 88c39bb496b973cd4ac7a259b871090447aff453b1f8926adfa4520bdde64d543f3f8be67cf1802e21dcf42c5b623fd069cdb06734297310357456ad95e0bf25 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
