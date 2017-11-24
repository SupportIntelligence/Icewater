
rule m2321_5214894adb2bd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.5214894adb2bd932"
     cluster="m2321.5214894adb2bd932"
     cluster_size="26"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shiz backdoor zusy"
     md5_hashes="['0b71fef5d0c02646dd4ad6ba5c2993e9','167cd2bcbed59c64aaf91fce17b5b930','b4e136b4f423664d59b39484d9a4cdf1']"

   strings:
      $hex_string = { 852de8be286ca4edd5cccfab490972b4a15c21c3f0d1315497f3a8f735b9448c016dfb3764e9ad2e0d3b1762f61ddfd6f5a67434aa8c8afc590c82ac864b4c71 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
