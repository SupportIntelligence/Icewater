
rule o3e9_525a3ec9c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.525a3ec9c4000b12"
     cluster="o3e9.525a3ec9c4000b12"
     cluster_size="215"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virlock nabucur ransom"
     md5_hashes="['03f9f5e0a12c5d34fdee36645146abf5','076aaf98918e456d765c9f6e873ed2ad','3df76893f579eb8c9646e65bba76f07a']"

   strings:
      $hex_string = { 0042a5f80046b0da002564b700c3b5a6002b78bf001c75ce0055b4c100ae60f500c6c3dd0088b1ee00588cd800266dff0087a4c2002180d5006fa8ea006591ef }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
