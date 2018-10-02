
rule o26bb_6a021c8148000000
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.6a021c8148000000"
     cluster="o26bb.6a021c8148000000"
     cluster_size="207"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="graftor multiplug malicious"
     md5_hashes="['2d615c44ab2f5235d654f13ac14752d47eb53e34','2f3e8492b37c72b5eda4ddb80dcdb4670f60dc0e','131c809f5192c63f6e57b0cbb92462d750d5914f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.6a021c8148000000"

   strings:
      $hex_string = { 4578004765745573657244656661756c744c6f63616c654e616d6500000000497356616c69644c6f63616c654e616d650000004c434d6170537472696e674578 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
