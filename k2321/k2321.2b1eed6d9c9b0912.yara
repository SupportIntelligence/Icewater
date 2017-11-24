
rule k2321_2b1eed6d9c9b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2b1eed6d9c9b0912"
     cluster="k2321.2b1eed6d9c9b0912"
     cluster_size="4"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba zusy emotet"
     md5_hashes="['25fd3d04f9316dfa6792cb0c4fc38e13','79f26728903ee0610f682c9ba9747a86','ce8b2269c22d9034a4284373dce9c036']"

   strings:
      $hex_string = { cececfdff9da6bc78f1e753aec56abf5d8d16360de07efbfd7c6e7952c169785925d486225c21242b458a4944a02d52a4491d0401df6c48880d6a022bd064bc0 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
