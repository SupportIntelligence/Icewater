
rule n3e9_3b1074ccdee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.3b1074ccdee30912"
     cluster="n3e9.3b1074ccdee30912"
     cluster_size="13"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="parite backdoor pate"
     md5_hashes="['0780a35cb6ccc4e571049bb0d90645c2','1881800dd947c33de61c41888d5d394c','efb9e681a461fc4b72f810c37ec7c45c']"

   strings:
      $hex_string = { d1a5564cb5b3ace9cdb26f3ebe20f346ee71ff97733c57101d5ebd79a396b427ca38e04d688895e7f99d7cc100cee19005fb62db9a6d898f8d2a129f5487c8c6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
