
rule m231b_4196ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.4196ea48c0000b12"
     cluster="m231b.4196ea48c0000b12"
     cluster_size="13"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script autolike"
     md5_hashes="['77b25820d9a14fa8eb431d65e0f08dbc80ad1968','e451b336b74ca64eb4ceb9511eaa55a336e98f0b','50fe5bf67cdf02899a94e6e082fb6b3a27f9931c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231b.4196ea48c0000b12"

   strings:
      $hex_string = { 36363435323b0a7d0a2e696e666f726d6174696f6e0a7b0a6261636b67726f756e643a20236462653366662075726c2827687474703a2f2f732e686169766c2e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
