
rule m3e9_29a5acc4f9646d16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.29a5acc4f9646d16"
     cluster="m3e9.29a5acc4f9646d16"
     cluster_size="44"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob chir"
     md5_hashes="['15a5e7b696c59b166f8ead47c1669820','1ab21999d762e2e8bcfee9412b9a1b3d','b890c62c743ed2eebc46fb04a08f402c']"

   strings:
      $hex_string = { 525344536686389c74b974428fc2d84f8d2e1bf203000000653a5c6678313972656c5c57494e4e545f352e325f446570656e645c6d6f7a696c6c615c6f626a2d }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
