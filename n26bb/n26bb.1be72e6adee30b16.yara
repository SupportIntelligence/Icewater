
rule n26bb_1be72e6adee30b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1be72e6adee30b16"
     cluster="n26bb.1be72e6adee30b16"
     cluster_size="10"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="debc malicious androm"
     md5_hashes="['0572fa46cd4765c51c88b14db0bf17a5a1a9db0f','fe71735c9d41dfcdedc663163f60f84dde8d16f9','f2d00f36d261a7c1e1d75ff311a6d14d553b3c38']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1be72e6adee30b16"

   strings:
      $hex_string = { eb0fe95c93feffbb03010380e8ba96feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c055688aa2410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
