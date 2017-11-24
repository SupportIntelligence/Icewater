
rule m3e9_29152541d99b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29152541d99b0912"
     cluster="m3e9.29152541d99b0912"
     cluster_size="71"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ursnif doboc polyransom"
     md5_hashes="['003d71265714fe7d3b03c47f2a800921','016e0ad6a3ce8cbd07686c0c130345c7','435cb1b6cb2f1e7e9838533a59be31e7']"

   strings:
      $hex_string = { 90b984ccb84295545cb82ff7793ab83d88bdd8b811bac3a9b80be80714b8371755dab8c2b56810b8f1b04e25b89f9d0ed3b8767ed62cb8fcd2c7e5b85ed4670d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
