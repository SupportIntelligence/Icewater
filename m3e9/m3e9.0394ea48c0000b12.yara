
rule m3e9_0394ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.0394ea48c0000b12"
     cluster="m3e9.0394ea48c0000b12"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="swisyn bner mofksys"
     md5_hashes="['431730a1f3ab59a35b03f08a8149c45a','46b5ff991e72a967577a7dfb786e265d','c3925c93b13449b62be4eded98acef61']"

   strings:
      $hex_string = { 4fb1d0e31b64838c7b79d5f90debdcb4b6956dbbafc6ed5a57cd81d3b292ca7565f46c67899b93493a66ba4aaae94d39d9364e70d473df7633c2982386f05fc9 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
