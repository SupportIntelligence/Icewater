
rule k2319_39156817ddbb0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2319.39156817ddbb0932"
     cluster="k2319.39156817ddbb0932"
     cluster_size="44"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script flooder loic"
     md5_hashes="['8c0a994c2b3ff268b57277a49f20e9b5a401bc0e','869e2861e557107c28a2a984e38fb5031aa4e8a4','cd3013514fa3422bc00ce424d1cde14fd3d91a1e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=k2319.39156817ddbb0932"

   strings:
      $hex_string = { 30535531464239734c46774d65436a6a68634f4d414141442b5355524256446a4c745a537654674e424549652f5752526e6d3355385243316e655164736d317a }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
