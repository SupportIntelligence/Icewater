
rule k2321_2914ad6d9c9b0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2914ad6d9c9b0b12"
     cluster="k2321.2914ad6d9c9b0b12"
     cluster_size="9"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet zusy"
     md5_hashes="['0edc6b9d3ab242e1ce4e87df1a831d8a','22dee8ee007dd5222cfbcac6388de893','f92160187a7cf2d42645721c74ab78fd']"

   strings:
      $hex_string = { cececfdff9da6bc78f1e753aec56abf5d8d16360de07efbfd7c6e7952c169785925d486225c21242b458a4944a02d52a4491d0401df6c48880d6a022bd064bc0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
