
rule m2377_199b93c9c8000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2377.199b93c9c8000b32"
     cluster="m2377.199b93c9c8000b32"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171121"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['4c6df690af8912612cb48d707baf5ab7','679d492a102902f4509886a32b917ce7','bdcf51b1a366480bf9e79663b4fbffbb']"

   strings:
      $hex_string = { 3936303330313636355c783236636f6c6f72735c78336443677430636d467563334268636d56756442494c64484a68626e4e7759584a6c626e516142794e6d5a }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
