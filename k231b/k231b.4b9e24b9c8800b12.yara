
rule k231b_4b9e24b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k231b.4b9e24b9c8800b12"
     cluster="k231b.4b9e24b9c8800b12"
     cluster_size="14"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="faceliker script autolike"
     md5_hashes="['31f6e762e60a7d0b23709ed8d1d00099034d0717','94203533d5602bddda797d8c1cd1e9bff752c3c7','e52c6e407dcf95054d256437900ea37f3188d191']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k231b.4b9e24b9c8800b12"

   strings:
      $hex_string = { 2a205374796c653a20274d264d273b205374796c652049443a2036360d0a2a2f0d0a626f64790d0a7b0d0a096261636b67726f756e643a20234537463343343b }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
