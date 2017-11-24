
rule m3e9_316338579cab1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316338579cab1112"
     cluster="m3e9.316338579cab1112"
     cluster_size="30"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="qvod viking jadtre"
     md5_hashes="['26c10b7c0453273a53d6012545513f89','4e11deac14a8a3a89586748050b9170a','c25407b19a16d0d066cf1e54f0769698']"

   strings:
      $hex_string = { 104c6743c690ba2abe94f8181193840663bdbd7570c2e315382b6a3be678a0f23f3977df44075220d957920ed249a95005b9b52e34b6fe61400cffaa1ec8eecb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
