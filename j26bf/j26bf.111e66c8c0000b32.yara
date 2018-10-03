
rule j26bf_111e66c8c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j26bf.111e66c8c0000b32"
     cluster="j26bf.111e66c8c0000b32"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="barys malicious tomc"
     md5_hashes="['365081a937524b7a7ef990f080f183ea2a0640a9','9967ff63de6192ac577ff12ec374f03228b1dc13','58a322344ce2275f81b92ec83522f801ccb22585']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j26bf.111e66c8c0000b32"

   strings:
      $hex_string = { 00546872656164536166654f626a65637450726f766964657260310041004d6963726f736f66742e56697375616c42617369632e4170706c69636174696f6e53 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
