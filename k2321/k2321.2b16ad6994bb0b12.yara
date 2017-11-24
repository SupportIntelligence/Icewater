
rule k2321_2b16ad6994bb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b16ad6994bb0b12"
     cluster="k2321.2b16ad6994bb0b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy emotet tinba"
     md5_hashes="['9c3ad27777b9f252432ad560e3ef191d','a01f4c6f6e6a1ab5efe577f7fa6e8008','f464b3bfbe2eb5dbaf88a6da20ca707a']"

   strings:
      $hex_string = { 1ec9cd8de4ce8864e786b32687b05203d9495a6eb846acd72a95729980bcbdeecbf06beff37d2683c366898402b54211a05107aa157aa534482d0e578ba2d4c2 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
