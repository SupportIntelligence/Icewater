
rule n26bb_591fb843cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.591fb843cc000b12"
     cluster="n26bb.591fb843cc000b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kazy loadmoney cryptor"
     md5_hashes="['fd803a1eb878c2eb20ed75395d1ba57ca7f84c92','79f5c45bf43120e219a6d9427e62ca8e3d8bbcb8','03167ae87cf1fbdc2a1d36626c092efd3878d59b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.591fb843cc000b12"

   strings:
      $hex_string = { c16c4cfee71294f67ebd8e6cf0d7f3f0bd39a7c2765a27003133686748fc877246e6f8ac69775cecb65ba8bec8006d718397c224a71cab848fdea40047b25cd3 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
