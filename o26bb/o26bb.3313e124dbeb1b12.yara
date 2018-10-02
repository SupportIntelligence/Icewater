
rule o26bb_3313e124dbeb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.3313e124dbeb1b12"
     cluster="o26bb.3313e124dbeb1b12"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="webalta malicious toolbar"
     md5_hashes="['c443837a69a93f28da25dc5c81cca3224921a1c7','f5474da1cc3cd11f69ebbbd1bb47dd6da5646366','5036755c3b93f0dfcb939e9184885b5ac3fb33dc']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.3313e124dbeb1b12"

   strings:
      $hex_string = { daeb0608e4740388e0aa925089e331d2f7b66081510080c2308813434909c075ed09c97fe94b8a03aa39e375f8585ec390558bec83c4d45756538945fca03bc7 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
