
rule o26bb_09bb6681dceb1932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.09bb6681dceb1932"
     cluster="o26bb.09bb6681dceb1932"
     cluster_size="4283"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy softcnapp adload"
     md5_hashes="['0146c83287cb7199e0fb8988886c3f71d1db2828','d946e2b921b4c05ed044e4a50ca28135c5d45db0','97ded5805024e3dd8f5ebfdd96ce6dec23917f0f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.09bb6681dceb1932"

   strings:
      $hex_string = { 56e8b17501008bd083c40c85d2741985f6740f8bca2bcf8a078804394783ee0175f55f8bc25e5dc3e887c0f8ffcc6a14b8651f5500e84a9a020033db8d4dec53 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
