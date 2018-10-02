
rule o3f8_496e5399c2201132
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f8.496e5399c2201132"
     cluster="o3f8.496e5399c2201132"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos smssend andr"
     md5_hashes="['ead9f6d494eca6184a1d7b6c8200a6815ce0feb8','00525bb848e170adef2ac83aed016d9511ec7b33','b2e1b08e053c289d1a83ff63835a8c42e5cf3c6b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o3f8.496e5399c2201132"

   strings:
      $hex_string = { b88de883bde4b8bae7a9bae38082000b5a68616e675061794d5346000f5a68616e67506179e8aea1e8b4b9e68f90e7a4bae6a186e590afe58aa800045a6f7066 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
