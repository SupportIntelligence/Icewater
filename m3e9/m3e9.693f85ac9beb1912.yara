
rule m3e9_693f85ac9beb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.693f85ac9beb1912"
     cluster="m3e9.693f85ac9beb1912"
     cluster_size="153"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['0175eedf5d7adb0303c487debdbce999','01922611593377e2ccf1fae23c29d4a1','2df4de60554ce30efa0684a64719d6d9']"

   strings:
      $hex_string = { 654c864752cba5bf38519004fb1816a88fc2a288823baf1a45b908570e9104be55dde19cd59dd6223231d95c1425eeac107f5f8435547a0b9311ab6abad26bbc }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
