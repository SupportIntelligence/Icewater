
rule k3f4_12a454569ba91114
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f4.12a454569ba91114"
     cluster="k3f4.12a454569ba91114"
     cluster_size="17"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="krypt bladabindi arrkp"
     md5_hashes="['055e38db1cd3ea1df85e4082721b6f6b','09f273b49f69b5ba793d2ac24266a1fb','f99573300e405cfba1e32de474abbf90']"

   strings:
      $hex_string = { 03e1120d0809018705f60619015d132f0819016213370811036d133e088100d00f850191007613140711037f134408190186044a08310295135608e900a513b7 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
