
rule k2321_13158651d8827916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13158651d8827916"
     cluster="k2321.13158651d8827916"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['4a922c6b2dd025d7f23b5b8341472b2d','c392ebdb2107596c9a46bc5fc8df966c','fe0d51f2a7793d068d368a21c8909cca']"

   strings:
      $hex_string = { 54391b083b4f7e2de7b795dfc36750034b6d5209830569657ca620bdf09c569be62be45ba86f840a0db12967d2c5becfa4cde5f24c6a2e68818c8dfc6b0fd613 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
