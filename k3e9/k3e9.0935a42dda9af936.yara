
rule k3e9_0935a42dda9af936
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.0935a42dda9af936"
     cluster="k3e9.0935a42dda9af936"
     cluster_size="8"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nimnul vjadtre wapomi"
     md5_hashes="['279eb5beda5aca8c36505f27e66037bf','4c10c5ad9934d4ddc8c2bbc0d29a91d2','b2c5957908c6e6f8fc51758cf4caf610']"

   strings:
      $hex_string = { 4fa3ff16c96c43d731847699f3ad87fe3439c54e4f6b8d64b7cb4c37e99bc059a9f54dccf6047ce0c6f76b413e62de9dfc29afdf5f2a60ca9a26cd38733bc3ef }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
