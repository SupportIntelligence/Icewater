
rule o26bb_4096ea48c4010b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.4096ea48c4010b12"
     cluster="o26bb.4096ea48c4010b12"
     cluster_size="82192"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickdz malicious adposhel"
     md5_hashes="['3d286712bf68d0a4164e976011d301a6e268d9b1','d5c666142ef4aa7b3405836ede646210a04ba7f7','5c846d39877c96dfaca39983e25b68a41e8f8401']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.4096ea48c4010b12"

   strings:
      $hex_string = { 45d8d408dab998704a63a76758442e3eed1330e4a59e17385d5764d5a2dd50b0d339d65559fceb48933a22e1889199bd042a3c8bfcf6cc162f8641c4150ab562 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
