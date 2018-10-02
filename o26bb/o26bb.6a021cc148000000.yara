
rule o26bb_6a021cc148000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6a021cc148000000"
     cluster="o26bb.6a021cc148000000"
     cluster_size="346"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="multiplug malicious fakedownload"
     md5_hashes="['a7829dc53c0ae970b1a763255edf632416af340a','2483318a1c9f13a56b695164c12c207e8d86d83a','0c3975c7d71017ea70b895dc4817a7a04f7381d6']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6a021cc148000000"

   strings:
      $hex_string = { 4578004765745573657244656661756c744c6f63616c654e616d6500000000497356616c69644c6f63616c654e616d650000004c434d6170537472696e674578 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
