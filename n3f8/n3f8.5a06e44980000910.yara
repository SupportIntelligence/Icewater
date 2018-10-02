
rule n3f8_5a06e44980000910
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.5a06e44980000910"
     cluster="n3f8.5a06e44980000910"
     cluster_size="51"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker piom"
     md5_hashes="['735c7def8189e67b21a31351846cc0ba09f4fa2a','df079495700f3f9964d83db3404b1199f0924b56','19ce39181fa122cc57b8991a612ca3697fe54448']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.5a06e44980000910"

   strings:
      $hex_string = { 106c0104000a016e10620104000c007230180850060a003800f3ff54422f007210f80702000a0254433300b1127120800123003901e5ff6e106001040028e003 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
