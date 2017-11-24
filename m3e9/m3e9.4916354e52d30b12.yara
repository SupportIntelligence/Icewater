
rule m3e9_4916354e52d30b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.4916354e52d30b12"
     cluster="m3e9.4916354e52d30b12"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob malicious"
     md5_hashes="['9e42fec22022b595698cccfa678e5b1d','cee584b6212c32b091866261998f86ce','ee79e989c8dd7c335aa08ce025dccdba']"

   strings:
      $hex_string = { 43fb5fefffae214dba542af1d5afbecdc808342d055515b16d074595191ccc635916b76edc646b2b98561470fc3dc2e1b561bc4392257ca0dde9a29b39de7aeb }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
