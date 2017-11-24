
rule n3e9_211c92c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.211c92c9cc000b12"
     cluster="n3e9.211c92c9cc000b12"
     cluster_size="54"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dropped injector yakes"
     md5_hashes="['04b2d440d94289d08f4f28685a62b731','0593e34573f6fdccc53e092ee57dec5e','5ef102ea76af4fd828e5fbe15d4c4e7e']"

   strings:
      $hex_string = { cbcacdcccfced1d0d3d2d5d4d7d6d9d8dbdadddcdfdee1e0e3e2e5e4e7e6e9e8ebeaedecefeef1f0f3f2f5f4f7f6f9f8fbfafdfcfffe01000302050407060908 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
