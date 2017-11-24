
rule n3e9_1191201aded30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1191201aded30912"
     cluster="n3e9.1191201aded30912"
     cluster_size="119"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ursu malicious kryptik"
     md5_hashes="['04e9340f0177e3ea635ee39bf58de7c5','066d2b96ad5b8547a09ef733df7fae76','21a7dd8d10c9146664febc30fe96a631']"

   strings:
      $hex_string = { 1fbb438ff67a5136924d637782a841bac10773fb9c4532dd0af000640de083279853f9f149e20372467d7ebe1e589dd1f254d3b4b73b6c7f95975e3e4c93e123 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
