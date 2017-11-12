
rule o3e9_4b124e86d7a74912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.4b124e86d7a74912"
     cluster="o3e9.4b124e86d7a74912"
     cluster_size="204"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="blackv malicious chinad"
     md5_hashes="['00c4ba7ed1ea555a81c9a54b69eccfdf','018c7d11c237197a4fc2e89c880b1ffa','14539c19512cc1aa460e891fbd95fe53']"

   strings:
      $hex_string = { bd8a2b6b8a4ee223f3041f680499da906b38767642762e5fba26e08c96a82ff460ede4e8d9650efa58dd7f74f66d269c6410dee48d6be9ecbe4b78a4be8fb48e }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
