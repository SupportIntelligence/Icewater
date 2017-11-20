
rule m2321_1b1cb5a1ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.1b1cb5a1ca000b12"
     cluster="m2321.1b1cb5a1ca000b12"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="picsys hidp prng"
     md5_hashes="['54a04be644e01b5b4bde154382598e43','932cc27b7be4a6e24bbdf99ebb303e04','d3eacfd0743344de8cd60283b98f0dda']"

   strings:
      $hex_string = { 8eb71f98419af6c57d5135ab9799b50df01412dbe18fbc1998c8eb9bd1d3bd73f1e4ea7e48160a34583a7269e3552d5e4d38445223a93663e5fe0f6cdec1a296 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
