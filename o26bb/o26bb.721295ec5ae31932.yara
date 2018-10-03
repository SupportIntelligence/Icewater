
rule o26bb_721295ec5ae31932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.721295ec5ae31932"
     cluster="o26bb.721295ec5ae31932"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="linkury zusy malicious"
     md5_hashes="['14dd03278d20cde64c97c9070c549f34d30853d3','75d92ac8fc8ce1e8cd1dbce156f594fb2e2b6f82','eb29854b1bc26e389eb656217553e4802340f6ff']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.721295ec5ae31932"

   strings:
      $hex_string = { cf8945cce8fee9ffff83c4048b55f885d274328a5f1380fb08732a0fb677198d879800000033c985f67e0d39500c741c4183c0143bce7cf30fb6c38994876001 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
