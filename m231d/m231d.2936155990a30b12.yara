
rule m231d_2936155990a30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231d.2936155990a30b12"
     cluster="m231d.2936155990a30b12"
     cluster_size="38"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="generickd hiddad androidos"
     md5_hashes="['717d1301039b3752dbaa45446f7ea305f9aaa751','da95536001115d242b37b70011ced72facdaf454','6b1367cfd3b6fb3922e1ee2b39b025947f3cfd53']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m231d.2936155990a30b12"

   strings:
      $hex_string = { b916236f4d7145e8f85a609967ab77dd43d3531933805e9c7297d624374a5ff7dc0edbaac0c6a789641d965b7ed51a26e136d7a22531927841e2f6c70af0fdb1 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
