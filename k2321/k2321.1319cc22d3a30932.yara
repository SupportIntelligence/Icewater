
rule k2321_1319cc22d3a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.1319cc22d3a30932"
     cluster="k2321.1319cc22d3a30932"
     cluster_size="33"
     filetype = "gzip compressed data"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hupigon backdoor razy"
     md5_hashes="['0252f735735efd475c81b17c80550efb','05976fcb6980a0fa5382903feb1376c7','83c9d24ea4de1f2941d10406bfc92823']"

   strings:
      $hex_string = { f7c1249d0a596f9e376b3c51331a4afc34a2c55f3df376a8d6429992b7a05a9f4362f595b329786977e2a1b844c72fd9e1e9d51ede8efbcff0790bbda3352d13 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
