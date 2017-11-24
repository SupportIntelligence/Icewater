
rule m3e9_593f16b0a7910932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.593f16b0a7910932"
     cluster="m3e9.593f16b0a7910932"
     cluster_size="974"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="unruy backdoor banito"
     md5_hashes="['00d7b5ac698882938b03a5cce1478994','00e9fafabaeb626e704186bdb2a1153f','038350bac2a93d9eb9c703439013a4f3']"

   strings:
      $hex_string = { 4624d0e141008b4e2868a81b00006a0151ff562083c40c3bc775085fb8fcffffff5ec38b4c241089461c3bcf7d07897808f7d9eb118bd1c1fa044283f9308950 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
