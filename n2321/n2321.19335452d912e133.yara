
rule n2321_19335452d912e133
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.19335452d912e133"
     cluster="n2321.19335452d912e133"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut shodi zusy"
     md5_hashes="['06ae6bd026ceaa5eba659aedcb5b4740','0c4c0bc8489b0f314693004dcc59bca7','ec303b874d0ecf45965a4dca81c60a7f']"

   strings:
      $hex_string = { a55536e761ce29b03571ff9caaa7e49d25381b150c73b33d115fa2e30a92d9cad2028e44e27c64fc7fec5d0f7054c779df930ed0393227bbb8a12e89cf338a6b }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
