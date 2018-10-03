
rule n2319_6994d4b9c2200b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.6994d4b9c2200b12"
     cluster="n2319.6994d4b9c2200b12"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="miner script coinhive"
     md5_hashes="['fb20633f2058f4a01ca7bd76b6980ad3389384a7','35d4f5ce8700f8e25f4f23a404a010bb5f225684','e805cb8d6f596228c2a89644dd9124aad503b39b']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.6994d4b9c2200b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
