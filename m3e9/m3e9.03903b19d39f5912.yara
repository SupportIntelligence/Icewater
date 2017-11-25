
rule m3e9_03903b19d39f5912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.03903b19d39f5912"
     cluster="m3e9.03903b19d39f5912"
     cluster_size="6"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader cobra"
     md5_hashes="['51a8d2b786ae4de37d87a3f11a872046','58a4998adf7fbe3ef2e9584a4367ca5a','bfd91e1414b6a7c98cf9b1810ce50e1f']"

   strings:
      $hex_string = { f647305072314059422b092229e60db9c81b640ef4a28a9c5188ffbc809b3db02e14658f234bd810cb5c4f91759801442496ead1f0e72fd26b6007b85a620bd3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
