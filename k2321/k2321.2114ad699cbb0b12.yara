
rule k2321_2114ad699cbb0b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.2114ad699cbb0b12"
     cluster="k2321.2114ad699cbb0b12"
     cluster_size="13"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="tinba emotet vbkrypt"
     md5_hashes="['075f414574e78685f71f3f9677676f7f','14ce56b278c3e7b9aa74e4dd2ab42919','fb7e5c656626f8aeb39f812174b9a929']"

   strings:
      $hex_string = { c19b69823787f3df1cc67f6308efcd21dc5d43b86fa47276a572de48e1bc41f4e4ec18c8de3180b3a33f7bd700d61bfd985bfab0e727f232a2c5a991daf8f020 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
