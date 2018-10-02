
rule m26bb_33b56a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.33b56a48c0000b12"
     cluster="m26bb.33b56a48c0000b12"
     cluster_size="68"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtu malicious badfile"
     md5_hashes="['1e492fa2d663f46e33adb76f014a99686bd411e8','3938a8fb02f62070ad0351678fab7204f7c19ac3','3703d919b8d3761a843f79eb9b1e1b7f71eb0b5c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.33b56a48c0000b12"

   strings:
      $hex_string = { 0d8b3983c104893a83c2044e75f383e00374098a1941881a424875f75f5e5bc3ccff25b8d24000535556578b7c2414833d84004100017e0f0fb6076a0850e898 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
