
rule n231b_6994d7a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n231b.6994d7a9ca000b12"
     cluster="n231b.6994d7a9ca000b12"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['7d78e7a7481dea38727dd1bff7f5aa006cb22a21','ce0398244d1d26ba7537fda42477552c49b18b47','8c0d419a31289be11dc59c5f39243c4db5576584']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n231b.6994d7a9ca000b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
