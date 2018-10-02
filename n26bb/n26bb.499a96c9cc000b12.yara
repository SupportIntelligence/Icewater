
rule n26bb_499a96c9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.499a96c9cc000b12"
     cluster="n26bb.499a96c9cc000b12"
     cluster_size="75"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="softonic softonicdownloader malicious"
     md5_hashes="['0927bb79af5668a1155cf27d840d33c8ad48664c','99fb34483348c92f0487eb34e231c4a0e147485f','9c38ce48de555bd38566de1a5357a464c0edb375']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.499a96c9cc000b12"

   strings:
      $hex_string = { cf8f2a3e1dfc338c44d1b18e4e7281b81a0bd771410e3f1ba205f912f77c3443f1741465532d01398264029c3c16bbd9c21e0c93ac9e1c6121588409f50603c0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
