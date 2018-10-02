
rule m26bb_0b469be1c6000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.0b469be1c6000b12"
     cluster="m26bb.0b469be1c6000b12"
     cluster_size="30"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious virut ajids"
     md5_hashes="['9640644a1584b2693f05cb33ba1e8cad2ed9ca1c','a82efb6633b094b5cdd5bd789320e11e645ecb8e','ed279158aa2b17771cb8eaff604b7b0257ab4ab2']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.0b469be1c6000b12"

   strings:
      $hex_string = { f5b835f84599d5821f60dad7c41b59075230905ef6adf9f378e6dc247c9b833904cb6180cdc02c026cc9650510e700e99a3f1401d232e875fa31981a09db736e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
