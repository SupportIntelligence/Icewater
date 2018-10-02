
rule m231d_2936155991a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231d.2936155991a30b12"
     cluster="m231d.2936155991a30b12"
     cluster_size="48"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickd hiddad androidos"
     md5_hashes="['160779efeaba1e288cbb23543ff49d9c1c1985b2','ac322499016c1bc252d5161cefd60e64cb95f931','81cacc4cd206c34ff5ec3413698bd39bad55ffdb']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231d.2936155991a30b12"

   strings:
      $hex_string = { b916236f4d7145e8f85a609967ab77dd43d3531933805e9c7297d624374a5ff7dc0edbaac0c6a789641d965b7ed51a26e136d7a22531927841e2f6c70af0fdb1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
