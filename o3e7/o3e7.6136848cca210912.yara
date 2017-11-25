
rule o3e7_6136848cca210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e7.6136848cca210912"
     cluster="o3e7.6136848cca210912"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="optimizerpro speedingupmypc riskware"
     md5_hashes="['0e7ac65069e956d5a14fc35c51deb259','b182e31de82885942be3ad69de8057c0','e405b506ecdda71d1b831a77438049c3']"

   strings:
      $hex_string = { 7cc8044d77fa505184375793fd64cb067e18784940a800e60fa327cf4cd2e8b0f58e839cb861e9acc691a74abc7db5d35d300ac57b9b12e709cd852fa943ca41 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
