
rule m3ec_524ca5c213eb6b96
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3ec.524ca5c213eb6b96"
     cluster="m3ec.524ca5c213eb6b96"
     cluster_size="22"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['38b53436da1c964eb8d32b82fc5322ba','3a3f37695a53fc461c17f4e902b867ca','ed74ff54f529689857a0ea7cc6c6332d']"

   strings:
      $hex_string = { 8945fc8985e0fdffff898ddcfdffff8995d8fdffff899dd4fdffff89b5d0fdffff89bdccfdffff668c95f8fdffff668c8decfdffff668c9dc8fdffff668c85c4 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
