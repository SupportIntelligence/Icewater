
rule o3e9_1112008eca600912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1112008eca600912"
     cluster="o3e9.1112008eca600912"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family=""
     md5_hashes="['297a30ccbd8ea25bd50fe493d827962d','4545ddadd4a45ab2c4f164db35d85ff3','f1b6fdd9c3905d4ccc7d68b96ba87ad9']"

   strings:
      $hex_string = { 5ab50176e4104c1545652b787e968b9b026d3b29eda5a79d4d114a9961bc6ac9aff52d09827f7b3dccfd862e48e23e14f4bada2275e6f271b7083964e1cfc706 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
