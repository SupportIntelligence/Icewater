
rule o3ea_4a1d97a1ca000b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ea.4a1d97a1ca000b16"
     cluster="o3ea.4a1d97a1ca000b16"
     cluster_size="1271"
     filetype = "application/java-archive"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos riskware smspay"
     md5_hashes="['003f469795a474d8386d62a5aeedb1d9','004988a365429bdf77c3a859c0e0bc7e','02bf336c858536dcded3687742d08869']"

   strings:
      $hex_string = { c8713a1858dc0a4f56cbfe1baf3ea199c561f3c6bb34d63f517612ad94aae211e770318ad244b49b62917bc037794aa3f0028b4d78a8862513cc8d08ba9a3965 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
