
rule k2321_09285923d9eb1912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.09285923d9eb1912"
     cluster="k2321.09285923d9eb1912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="vobfus conjar autorun"
     md5_hashes="['1ffa28131cb4bc684c4c01de2057142b','401c48d1ef3338ccaf282312f82347e2','9a6409004a3facf96e72e45ab3d3a16c']"

   strings:
      $hex_string = { d47f296b4bebbfb1095c473546acd6bac70c3d0a39382aaa3cbc14160134929a2fe796ab5443d1ad9cce59f710c269dcc9f6dea693ae66dd1121cff9b3b60699 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
