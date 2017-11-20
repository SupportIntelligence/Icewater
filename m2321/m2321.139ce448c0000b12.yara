
rule m2321_139ce448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.139ce448c0000b12"
     cluster="m2321.139ce448c0000b12"
     cluster_size="17"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="swisyn bner mofksys"
     md5_hashes="['01022cd20715f07a2dc22a9b5460ee49','0ee272b2af82a9677a400d4ae3803022','fea5b4a8f82b3d8644e847febc90372b']"

   strings:
      $hex_string = { 4fb1d0e31b64838c7b79d5f90debdcb4b6956dbbafc6ed5a57cd81d3b292ca7565f46c67899b93493a66ba4aaae94d39d9364e70d473df7633c2982386f05fc9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
