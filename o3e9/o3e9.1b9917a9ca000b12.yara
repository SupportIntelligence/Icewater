
rule o3e9_1b9917a9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3e9.1b9917a9ca000b12"
     cluster="o3e9.1b9917a9ca000b12"
     cluster_size="9"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="installcore dealply unwanted"
     md5_hashes="['3615e2da42307bfe59bec827c6b973e4','3f058ec1fba432da9aed3bde3737c3a3','e65175c9cabfde33539552ba19d21f2b']"

   strings:
      $hex_string = { ef3e45be7a21ba7235b14684a8aaed7cc45377c5fdff636f06b84bd6589499b0763bd8232ad3dce95f57839dc8a28cea8501ceabb69c5b3ae89837c19250b328 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
