
rule n26bb_1bc59c94cee30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1bc59c94cee30932"
     cluster="n26bb.1bc59c94cee30932"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="dealply malicious filerepmetagen"
     md5_hashes="['acad5d4a44855459a8e626662c26dc6fb7ac9610','6d55054e355db86dfede93c658933afffb256a64','a7d1c63c0c87ee8f6552bddac7ec7b6799827289']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1bc59c94cee30932"

   strings:
      $hex_string = { 38d974188d7431074f75f28b40dc85c075dc5aeb1b8a1a8a4e06ebe88a5c3106321c1180e3df75ed4975f18b065a01d05f5e5bc352515384d27c03ff50f431d2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
