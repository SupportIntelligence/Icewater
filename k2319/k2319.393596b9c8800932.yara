
rule k2319_393596b9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.393596b9c8800932"
     cluster="k2319.393596b9c8800932"
     cluster_size="111"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="kryptik script diplugem"
     md5_hashes="['ed1da728bd0af9c4c30a1f1cbe66f2ccc61fc1ac','57eec7a996b9992d04b9f52de00a8c48b647c37e','6cdb8d25726d44ec6cb9596e3df3d4a24547ef04']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.393596b9c8800932"

   strings:
      $hex_string = { 535b525d213d3d756e646566696e6564297b72657475726e20535b525d3b7d766172204c3d28283131382c30783741293e283133362e3445312c39352e293f28 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
