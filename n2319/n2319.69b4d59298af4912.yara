
rule n2319_69b4d59298af4912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.69b4d59298af4912"
     cluster="n2319.69b4d59298af4912"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinminer"
     md5_hashes="['a56dbeb7e7a2fd5bd7d027ef17ceaff8b34c6444','6251e76335c3f76589d39dc497e5773a3909ce13','9c400851066d1d155fadee519d720e3879189973']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.69b4d59298af4912"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
