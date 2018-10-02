
rule nfc8_4894ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=nfc8.4894ea48c0000b12"
     cluster="nfc8.4894ea48c0000b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos svpeng"
     md5_hashes="['fbeced54975b53f6aa2ef67ee2e4aaca5d38106d','25981f456063725091c49208824a795444999c0c','50298d78e4dcf92ddea018ef46460cbd4a404ca6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=nfc8.4894ea48c0000b12"

   strings:
      $hex_string = { b7b4a8467937c0680a7b22fdf0a357435a00f118ac0c8547d60e7a2fb8f99ca1326a745c6b9d1672c7ef43afbf3bbc9f057ee2bd02ab5389dbf7971b360350de }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
