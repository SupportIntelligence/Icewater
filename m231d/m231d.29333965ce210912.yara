
rule m231d_29333965ce210912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231d.29333965ce210912"
     cluster="m231d.29333965ce210912"
     cluster_size="18"
     filetype = "application/java-archive"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos ewind andr"
     md5_hashes="['03fba7d37d2d1814d6668e49b08f79a8','1c55c5a8217e2048f77091a0c24822ba','ef1aee88ecfb1a186700486625155d38']"

   strings:
      $hex_string = { 19ed2fd499c75f30c6385066f4c013bf3df22196b198794db6d05b90d71309f840f1eeda2270d8c114053ec4e7296afca32486642d2f69ab0665decd45585a56 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
