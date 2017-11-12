
rule n3e9_143618e948800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.143618e948800b12"
     cluster="n3e9.143618e948800b12"
     cluster_size="107"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['01467dbb43f3e5f568932a3f6633a6cf','047c935f1326d988aaef159a0129630e','2f5495b6511dadd6875d6092a7318fa6']"

   strings:
      $hex_string = { e75640fd10a0f4bad7504866011a8606c5bd38706d5f4a115380ab24b2998e75bba17b2e14c04d8433fbae07e0b9c85e7f896ae60ba5e9cf3d628d4cff76b473 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
