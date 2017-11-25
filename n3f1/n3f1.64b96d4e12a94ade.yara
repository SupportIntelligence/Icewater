
rule n3f1_64b96d4e12a94ade
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f1.64b96d4e12a94ade"
     cluster="n3f1.64b96d4e12a94ade"
     cluster_size="40"
     filetype = "application/zip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos gudex revo"
     md5_hashes="['02155126af475e96c956aabd0ebccaac','053b51f6feb94568590b3ce5ca84469c','77b891f3c50ee18307f7cb96ac22748e']"

   strings:
      $hex_string = { b100727138f9362fce05229789b75b8d88a96355f4a529e446e84ca6e66a46e73cc970120cd2de1749d30ef8e31135bf574ffa47d70b9f944ee2b3be58191092 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
