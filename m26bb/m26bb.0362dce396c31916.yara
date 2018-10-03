
rule m26bb_0362dce396c31916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.0362dce396c31916"
     cluster="m26bb.0362dce396c31916"
     cluster_size="82"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore malicious unwanted"
     md5_hashes="['da3041363cbed42b2e0c33fb92103a23e9968c8d','cb8d09798901743375cda1a5e7bc6e299a39c2f1','f94bc0465a094f278de4437df4e45d2b59d15e13']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.0362dce396c31916"

   strings:
      $hex_string = { 40ec85c075de5aeb1b8a1a8a4e06ebe88a5c0e06321c0a80e3df75ed4975f18b065a01d05f5e5bc3525153ff50f431d28d4c2410648b1a8919896908c74104ed }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
