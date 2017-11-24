
rule k3e9_219cea48c0000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.219cea48c0000932"
     cluster="k3e9.219cea48c0000932"
     cluster_size="39"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="nitol fdld dropped"
     md5_hashes="['159dbb4304c9d238d536baf96a03e132','1f8096bdad26de6a8b924da0fcd4c0b9','722608c0a895a9af0578bf95c2f51e3e']"

   strings:
      $hex_string = { d32f4c506cea84c5a651b16f726d8b0e58b1e69ff0c7ba9d780cce37c9c2e74d91b64f48c0ad9554fdd6f3acdf7a810d68cf860267f587b47ffa650929061b34 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
