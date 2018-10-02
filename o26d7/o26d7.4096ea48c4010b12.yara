
rule o26d7_4096ea48c4010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.4096ea48c4010b12"
     cluster="o26d7.4096ea48c4010b12"
     cluster_size="81910"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz adposhel bjuwvk"
     md5_hashes="['95586e0ebe74d4006db094f359427028ece63a10','59ca1ed9a630393cbb9d5e580de2ca87b0e0e49c','7f67db000c324173a1dae1067eb3bf2f656ff044']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.4096ea48c4010b12"

   strings:
      $hex_string = { 45d8d408dab998704a63a76758442e3eed1330e4a59e17385d5764d5a2dd50b0d339d65559fceb48933a22e1889199bd042a3c8bfcf6cc162f8641c4150ab562 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
