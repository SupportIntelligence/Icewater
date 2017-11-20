
rule i3ed_1b90dfa959eb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.1b90dfa959eb0912"
     cluster="i3ed.1b90dfa959eb0912"
     cluster_size="299"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="backdoor padodor symmi"
     md5_hashes="['001d8df075a1d1dc772b0f4f00a50dd9','015cda91106a56f41c8f973a7d52bd70','170b3d013686a21570d1bba0b40632c8']"

   strings:
      $hex_string = { 7b088d0c768b348fe962ffffff31c0eb19558d6b106aff53e8a5feffff83c40c6a0be83304000083c4045d5f5e5b89ec5dc35589e5535657837d0c017505e823 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
