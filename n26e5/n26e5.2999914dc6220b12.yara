
rule n26e5_2999914dc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26e5.2999914dc6220b12"
     cluster="n26e5.2999914dc6220b12"
     cluster_size="23"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious filerepmalware kryptik"
     md5_hashes="['805f11edc0d9d2ecab55e89d3f8698b558f9a90b','6e572f498a9db714fcb7688f29f8a75fa9cf8f13','263d1233591e2a414f4b16a3f0887d6692537d85']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26e5.2999914dc6220b12"

   strings:
      $hex_string = { a1fc25fbad7ced281302053d383fa4cace6e7346bfa8625c6097331c1235557501363a47c32e0952405b8f85cb8a504fb7ff6c82ccf6ab2da7819bf063c074f2 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
