
rule n2319_691457a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2319.691457a9ca000b12"
     cluster="n2319.691457a9ca000b12"
     cluster_size="33"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="script miner coinhive"
     md5_hashes="['0b05524517c986a97882fd7425654aa59f832f90','b84ec291b28cff1a42fd91b08c75d65babdbe940','6be82533ebb0368bf5e47ec898ef2c4e4ba6cd8f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n2319.691457a9ca000b12"

   strings:
      $hex_string = { 313032343b766172204d41585f5441424c455f53495a453d4d6f64756c655b5c227761736d4d61785461626c6553697a655c225d3b696628747970656f662057 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
