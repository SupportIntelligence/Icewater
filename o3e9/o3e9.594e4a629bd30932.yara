
rule o3e9_594e4a629bd30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.594e4a629bd30932"
     cluster="o3e9.594e4a629bd30932"
     cluster_size="8"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['172cc798b86431e804bd65b135beaf24','23089ec06f0af94d192a3b31daf74314','f5a542608853d652957100c55b7380e4']"

   strings:
      $hex_string = { 006f002000260041006c006c000600260043006c006f0073006500040042006b005300700003005400610062000300450073006300050045006e007400650072 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
