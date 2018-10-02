
rule o26bb_3353e124dbeb1b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.3353e124dbeb1b12"
     cluster="o26bb.3353e124dbeb1b12"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious webalta toolbar"
     md5_hashes="['b8ef5a12c5de03fb02fef8a94d3d06a3b28986c2','17b6d7ce46ff630421d27667db36768017928104','a327df6396725ea0671d9c331aebd4b106f69519']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.3353e124dbeb1b12"

   strings:
      $hex_string = { e45dbf7c29edf68eef997df2c123639e3e3a3db9de6a44a91940df03fbe8f4dc606e7a1b6b83caf3c5d5b47ef0d851cf534beb9bb1b54ea4ec077ba7674d94ad }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
