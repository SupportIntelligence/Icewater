
rule o3e9_1112244bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1112244bc6220b12"
     cluster="o3e9.1112244bc6220b12"
     cluster_size="413"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installmetrix installmonster bundler"
     md5_hashes="['015d9d835b51b04cac7b6cbe9f686666','021b7f49e504fb68bdd72b5aaaaf9f1b','0c3d1a180b53acddf5afda34713ea116']"

   strings:
      $hex_string = { f931b8f501eafad19c6ce726ade034bdf00003cb420ff77c3276ffba7ef3b65a0ae273659d62e9a45c773aca4146157f6b3ab1fc08236e82d32c59a922ed1267 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
