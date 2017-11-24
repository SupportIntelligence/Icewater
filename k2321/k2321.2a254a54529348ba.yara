
rule k2321_2a254a54529348ba
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2a254a54529348ba"
     cluster="k2321.2a254a54529348ba"
     cluster_size="4"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="zusy tinba backdoor"
     md5_hashes="['43e0da9e12b1d2649aa179e677e4ba55','89042b4812e115cfb2a921cf7efdbf7d','fde518cfd5c6597b08c86018abaf94cb']"

   strings:
      $hex_string = { 756dc372ab8c61cbfd63e9bec68230ec8ed7f10cbfeac7569351337e4d5311b0028fed0a86b12d7d252bd3e10d6599b73e1d6a81cf8a45c8e766047f18d11958 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
