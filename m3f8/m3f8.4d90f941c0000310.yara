
rule m3f8_4d90f941c0000310
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.4d90f941c0000310"
     cluster="m3f8.4d90f941c0000310"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="banker androidos gugi"
     md5_hashes="['1a1136a91254d0cc81ffdb0dd137b42731c116e3','f40a13fb9fa9e24c800eaf579f5f58c237d157ee','c586fd39db34de23f838287318b35cad77543d71']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.4d90f941c0000310"

   strings:
      $hex_string = { 543b000454595045001955524c20626c6f636b65642062792072657772697465723a2000025553000b555345525f43414e43454c00055554462d38001d556e61 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
