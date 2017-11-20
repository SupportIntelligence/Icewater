
rule m3e9_3163387649af5112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3163387649af5112"
     cluster="m3e9.3163387649af5112"
     cluster_size="125"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod autorun"
     md5_hashes="['04570caa121377e9f56b57b051ef0d19','098cf028c40a503129036343d3fafd80','a238cdec4f702adc7414f6a4821119ef']"

   strings:
      $hex_string = { 725f847b9a46814ccc7cd0de43c9a171fae65733fdb49feb28dda5b66d127948aeb8c2c649e203f765bfd71bb105552e7a60fcaad1ba3f7707b77f7e382facea }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
