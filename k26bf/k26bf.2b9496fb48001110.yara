
rule k26bf_2b9496fb48001110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k26bf.2b9496fb48001110"
     cluster="k26bf.2b9496fb48001110"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious attribute"
     md5_hashes="['aec0888dd9bd834e0f555e62cb4a2912bbf8e685','e840a8432ed3db711812dbf9cd0d04b911e699e7','6d07ba9c2e50d61f9ac28afbbf2aa10674747c87']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k26bf.2b9496fb48001110"

   strings:
      $hex_string = { 282d00000a170b180d03472c76190d733600000a13041a0d11041717733f00000a13051b0d11050216028e696f4000000a1c0d11056f3c00000a1d0d1104166a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
