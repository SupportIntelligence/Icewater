
rule m2319_2b93130289056d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2319.2b93130289056d16"
     cluster="m2319.2b93130289056d16"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['00db5cc990c2c266a144ae7d0881ca9c','3be3bd85209d47e6e63c67f1bcb95917','f518b3f65e42f72a839756bc32b09211']"

   strings:
      $hex_string = { 76312f762d6373732f3336383935343431352d6c69676874626f785f62756e646c652e637373277d2c2027646973706c61794d6f646546756c6c2729293b0a5f }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
