
rule k3f4_2194813fca200b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.2194813fca200b32"
     cluster="k3f4.2194813fca200b32"
     cluster_size="75"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="bladabindi zusy backdoor"
     md5_hashes="['06369707778f85d299a232d137e0ea95','083f9317c354e7e8928053d90d29a63a','524b755b875039aa6c8f8364175e90d4']"

   strings:
      $hex_string = { 2a8bf65e6d83914ad0e740ff8898ed3ea69b17acf036127147fa5a9a57a81e0a76afec8424f239c066624b0b02b014c06720dbca22a4fb8ed1c331b2dd26a369 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
