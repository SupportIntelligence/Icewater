
rule m2321_3b199cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m2321.3b199cc9cc000b12"
     cluster="m2321.3b199cc9cc000b12"
     cluster_size="6"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['1d874ce72b87fef1fd52468e150ce96c','3bfe4abd891736c02a259194e1407599','fab4ea9f5ccf4d2dcb2c9941d35d5ad3']"

   strings:
      $hex_string = { ec454422657d4d13c72920ff15325a71b09ec4575d730243c56c049a8c8ff6c15b53ed2e12f3418932f7dc092d84e82c60318eca6f9de5a10dbe9882886e2150 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
