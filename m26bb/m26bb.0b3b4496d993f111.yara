
rule m26bb_0b3b4496d993f111
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.0b3b4496d993f111"
     cluster="m26bb.0b3b4496d993f111"
     cluster_size="68"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious ransom gandcrab"
     md5_hashes="['9bb8912aa6665dc0a26e7b4732a4678259315c02','97ef62ed950fd472a3029336bf2993a96db92eba','3cd9f4f6e5d755d648fdc039fba184a26168ce6e']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.0b3b4496d993f111"

   strings:
      $hex_string = { e23e5a27eb590e7aefdd8841ac38947b6be9a6b8f3bff8610c6cee4c3b35bc8d23977925d0cb1947e5d9b6a88c4b8aa55205e6761e7fa3c73f9c569b77303c09 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
