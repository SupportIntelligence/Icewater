
rule m2321_1294894adb2bd932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1294894adb2bd932"
     cluster="m2321.1294894adb2bd932"
     cluster_size="11"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shiz backdoor zusy"
     md5_hashes="['06fae71cb2dcb2e86bdd70460b0d77f7','0fc2009c1fe4ca52c6d24bcda2e46b0b','b7bdb0ff6073b07cbc3e5a3911381d39']"

   strings:
      $hex_string = { 852de8be286ca4edd5cccfab490972b4a15c21c3f0d1315497f3a8f735b9448c016dfb3764e9ad2e0d3b1762f61ddfd6f5a67434aa8c8afc590c82ac864b4c71 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
