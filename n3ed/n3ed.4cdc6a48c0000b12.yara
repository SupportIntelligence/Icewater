
rule n3ed_4cdc6a48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.4cdc6a48c0000b12"
     cluster="n3ed.4cdc6a48c0000b12"
     cluster_size="306"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit nimnul bmnup"
     md5_hashes="['02c82cc4b5bbdb1d087b24f0e5fc644d','03d19db798693555ba9ef59ffb2f8f6b','1dded3bf8d058f14b4fe3edd5cb55897']"

   strings:
      $hex_string = { 403bc672be8b4dfc5ee8b3a3ffffc9c3558bec83ec1ca1f481011053568b750833db3bf38945fc570f845401000033d233c039b0688a0110746583c030423df0 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
