
rule o26d5_484fea49c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d5.484fea49c0000b32"
     cluster="o26d5.484fea49c0000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious dangerousobject"
     md5_hashes="['4afd9e5a26f4303da850e77cc2af2197fe5dd809','98bffbcdd6d641906256816f54e038bdc5d752ac','0ac6959def48a01185d219ed7eba130c3ad5a008']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d5.484fea49c0000b32"

   strings:
      $hex_string = { 6954f8c0895966ef9a24b40d9899a6a83751950a96eb60e89cdece0ec274302c9b6eb7b31b708a1cc1e49da7f0aa550ca0c8725a071618df7f007b7c92caf43e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
