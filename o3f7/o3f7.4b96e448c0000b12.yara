
rule o3f7_4b96e448c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o3f7.4b96e448c0000b12"
     cluster="o3f7.4b96e448c0000b12"
     cluster_size="91"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['014c92612d51246d096ceb826351e4fd','051c6bbe575462502ca924c974a90ddd','2fcbe694c7f487ab4390b4663dc9c194']"

   strings:
      $hex_string = { 53c4b04ec4b05a2054c39c524bc4b05945262333393b444520322e20545552204845594543414e493c2f613e0a3c7370616e206469723d276c7472273e283129 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
