
rule n3e9_2db31cd6efe91932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.2db31cd6efe91932"
     cluster="n3e9.2db31cd6efe91932"
     cluster_size="5"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="dealply bundler malicious"
     md5_hashes="['1733a418414f9cc90a712af1a3a3487a','a52edf80e427e73392772e81fc864677','e41e1fdf997528390f9ad72919dd5977']"

   strings:
      $hex_string = { 00f0bf465d6bef5355d53f5d514a085655e53f9a9999999999c93f9a9999999999d93f333333333333e33f9a9999999999e93f744529215855c53fa3aeb5f7a9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
