
rule n3f8_5a06e449c0000110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f8.5a06e449c0000110"
     cluster="n3f8.5a06e449c0000110"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos banker piom"
     md5_hashes="['1a1a7f29a1fd4d7138ca67f9c186138bb3bc86aa','3d21f4da4fc4b9cca099bad10a51620aeb718890','228155088642c0b62adf680754fcc9bd150f7ab3']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n3f8.5a06e449c0000110"

   strings:
      $hex_string = { 106c0104000a016e10620104000c007230180850060a003800f3ff54422f007210f80702000a0254433300b1127120800123003901e5ff6e106001040028e003 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
