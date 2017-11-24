
rule m2321_093054d0d9027916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.093054d0d9027916"
     cluster="m2321.093054d0d9027916"
     cluster_size="51"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="filetour jacard riskware"
     md5_hashes="['07396245fe5e759509adc3270efc7e85','0a4f6c70fdaaa5832da5c8fdfcf27c6a','3d4dd18c7147dfa45ded4d75df773ae0']"

   strings:
      $hex_string = { d068b22fd7a479c3e470325aa1aed16c0792bc40125f0d9c2481152c1fc17d82f5628edb41f81805cd2aed394742aa547ad373bf11dfc000d92db5e1a284c465 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
