
rule k3ec_37155cf1dcc10b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3ec.37155cf1dcc10b16"
     cluster="k3ec.37155cf1dcc10b16"
     cluster_size="8"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious engine heuristic"
     md5_hashes="['40ab4df3c21c96fba73e18a06afcb039','4e3f4beef3a7449c144bd525e3679dc1','fe180dc76975a6b3835d04d0a38ee998']"

   strings:
      $hex_string = { c3cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
