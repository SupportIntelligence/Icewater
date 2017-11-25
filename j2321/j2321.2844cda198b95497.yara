
rule j2321_2844cda198b95497
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2321.2844cda198b95497"
     cluster="j2321.2844cda198b95497"
     cluster_size="10"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="generickd waski androm"
     md5_hashes="['07bec62a36200988262d05140599c489','0e033536eb7b20c88f949acaaba2cbd8','efe964cfff906441ebe0ed815f58eac4']"

   strings:
      $hex_string = { cb2b35c9de3e29b6b333f6b444721ac5499a9ad2ef7bf74e1febec3c76fa5ed69b639dbf94adab3a5577a0a2e240dd8d936b6f26b627d55db992d9bcf57566e6 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
