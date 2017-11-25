
rule m2321_03903b19d39f5912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.03903b19d39f5912"
     cluster="m2321.03903b19d39f5912"
     cluster_size="12"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre trojandownloader axzd"
     md5_hashes="['09b4cc21ac946181e3de0cdbd6d76808','206ef60115fa7e26aa46577a07dc9b39','febbb7df212cd44856203bdc11cb33c0']"

   strings:
      $hex_string = { f647305072314059422b092229e60db9c81b640ef4a28a9c5188ffbc809b3db02e14658f234bd810cb5c4f91759801442496ead1f0e72fd26b6007b85a620bd3 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
