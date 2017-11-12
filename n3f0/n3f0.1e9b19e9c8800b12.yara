
rule n3f0_1e9b19e9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f0.1e9b19e9c8800b12"
     cluster="n3f0.1e9b19e9c8800b12"
     cluster_size="7436"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd mira otorunp"
     md5_hashes="['000eb6dee5b7dcc69ea4fc103878e405','001c456ebf716d335de00170c45e61d0','00dd0876e5f9a6769b86132cc8da6ce7']"

   strings:
      $hex_string = { d801e4e2331a291895a9ce3f3d479eaa09cbb545ff5a3959efe4207f435d7b240450fe1a65d12bbaadca63828827fee859be582563fe9e6bb3d4cbba3e61887f }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
