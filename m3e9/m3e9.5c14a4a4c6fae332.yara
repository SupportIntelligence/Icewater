
rule m3e9_5c14a4a4c6fae332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.5c14a4a4c6fae332"
     cluster="m3e9.5c14a4a4c6fae332"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus barys wbna"
     md5_hashes="['22f5ad93dc07cae697db25f0730212bc','7538128fc0cd58fcdc0b340678c0d655','dad976bd7a82db20a8e77f12532fa8f0']"

   strings:
      $hex_string = { dbddd8c2c0bdb57dab95978e1e3a69d8f2f5f5f5f2ca4b480000000d2f2f2c52c0cdcddbdbdbbb30060b0b2b2b2b2c3d78cdd8c2bdb57b7d79969a90181f67d9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
