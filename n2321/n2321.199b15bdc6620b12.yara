
rule n2321_199b15bdc6620b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.199b15bdc6620b12"
     cluster="n2321.199b15bdc6620b12"
     cluster_size="63"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="amonetize aqrr classic"
     md5_hashes="['00f5c0bd346a2bcf77cc6b576517bf02','0b237e9cbe0375e565c18b778b035d41','4189b56fb7263269edc1726ad11ca251']"

   strings:
      $hex_string = { fa6776de7a98bf7900ad840d384fbb2a3725e0dc9d0e73770ccc5d7ddaaed1a76d91d4643316bd092fca7521c495669ca2a8147f1e9fa13028e344fc36c517c9 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
