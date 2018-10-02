
rule m26bb_267641c69e934b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.267641c69e934b16"
     cluster="m26bb.267641c69e934b16"
     cluster_size="1104"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="adposhel speedupmypc arbe"
     md5_hashes="['3cd5b0770c78fe8eaf4e66829fc4eddc7fa6a1a2','10a460f520015bb989c88d8b600a361235a7b715','bfebdeca32a8283a7bcd45e0731d5c52fd2e8a21']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.267641c69e934b16"

   strings:
      $hex_string = { d6be54d16e00f0cdfeb44d596d62057ac8a157ca43f2d7a0ef670e467cc77d29e6738d6964e2c3acaf7813e1e9c099ad9345ff42b66c22e84788203792bc26df }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
