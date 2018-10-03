
rule n26bb_5594ad49c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.5594ad49c0000932"
     cluster="n26bb.5594ad49c0000932"
     cluster_size="62"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virut malicious virtob"
     md5_hashes="['5435090851c84c6fd3dfe72bcabefc8129627541','e823647d04886c598fef3e6be8ff16eb9d4b9e5d','2d25d28cbd733b9133f5d88d2695b53179409134']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.5594ad49c0000932"

   strings:
      $hex_string = { 46233d7593c05701debd7780c835e2181a69e802d34e280ac7605870322a3066c94bac4a82cfb04d212caf9bfbd4be0f5a5b7ee18bbb7cf1277afcf99f799dab }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
