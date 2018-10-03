
rule o26d7_09145998dabb0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26d7.09145998dabb0912"
     cluster="o26d7.09145998dabb0912"
     cluster_size="63"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180909"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy kryptik amonetize"
     md5_hashes="['ef11b5bbe8eedc3ab7beb2d2238f89d651d04e00','28230382525ab9ac37dfe082057bfe113e9dee41','d07448194456269de5c2baebd048cc9803d3c444']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26d7.09145998dabb0912"

   strings:
      $hex_string = { 3ec0fb496c80855989123d46b57f745ed5d7d6d34dca538dea568d7310355c49ee040b7e72318d4380578df3820d48046687974200008d821f8b400288c0fb44 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
